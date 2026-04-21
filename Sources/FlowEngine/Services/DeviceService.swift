// Singleton that manages Device CRUD, param resolution,
// validation, and bootstrap.
//
// Thread-safe: @unchecked Sendable + NSLock (same as SecuredBox).

import Foundation

public final class DeviceService: @unchecked Sendable {

    public static let shared = DeviceService()

    private let lock = NSLock()
    private var _devices: [Device] = []
    private let store: DeviceStore
    private let _registry: ToolRegistry?
    private let keychain: KeychainProtocol

    /// Registry accessor: uses injected instance if provided, otherwise falls back to shared.
    @MainActor
    var registry: ToolRegistry { _registry ?? .shared }

    // MARK: - Init

    private init() {
        do {
            self.store = try SQLiteDeviceStore()
        } catch {
            fatalError("Failed to initialize device database: \(error.localizedDescription). Delete ~/Library/Application Support/Goodboy/goodboy.db and relaunch.")
        }
        self._registry = nil
        self.keychain = Keychain.devices
        reload()
    }

    /// Testable init: inject any DeviceStore, optional ToolRegistry, and optional keychain.
    public init(store: DeviceStore, registry: ToolRegistry? = nil, keychain: KeychainProtocol? = nil) {
        self.store = store
        self._registry = registry
        self.keychain = keychain ?? Keychain.devices
        reload()
    }

    // MARK: - CRUD

    public var devices: [Device] {
        lock.lock()
        defer { lock.unlock() }
        return _devices
    }

    public func get(id: String) -> Device? {
        lock.lock()
        defer { lock.unlock() }
        return _devices.first { $0.id == id }
    }

    public func devices(forTool toolId: String) -> [Device] {
        lock.lock()
        defer { lock.unlock() }
        return _devices.filter { $0.tool == toolId }
    }

    public func save(_ device: Device) throws {
        lock.lock()
        defer { lock.unlock() }
        try store.save(device)
        if let idx = _devices.firstIndex(where: { $0.id == device.id }) {
            _devices[idx] = device
        } else {
            _devices.append(device)
        }
    }

    public func delete(id: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard let idx = _devices.firstIndex(where: { $0.id == id }) else { return }

        try store.delete(id: id)
        // Keychain key format: {device.id}.{paramKey}
        keychain.deleteAll(matching: "\(id).")
        _devices.remove(at: idx)
    }

    public func reload() {
        lock.lock()
        defer { lock.unlock() }
        _devices = (try? store.loadAll()) ?? []
    }

    // MARK: - Keychain (delegates to Keychain.devices)

    /// Write a keychain param. Key format: {device.id}.{paramKey}
    public func setKeychain(deviceId: String, paramKey: String, value: String) throws {
        let account = "\(deviceId).\(paramKey)"
        try keychain.save(account: account, value: value)
    }

    /// Read a keychain param. Key format: {device.id}.{paramKey}
    public func getKeychain(deviceId: String, paramKey: String) -> String? {
        let account = "\(deviceId).\(paramKey)"
        return keychain.load(account: account)
    }

    /// Presence check for a keychain-backed param. Does NOT read the secret
    /// payload, so no macOS Keychain ACL prompt is shown.
    public func keychainParamExists(deviceId: String, paramKey: String) -> Bool {
        let account = "\(deviceId).\(paramKey)"
        return keychain.exists(account: account)
    }

    public func clearKeychain(deviceId: String) {
        keychain.deleteAll(matching: "\(deviceId).")
    }

    // MARK: - Verification state
    //
    // Three intent-named methods. All idempotent, all persist immediately.
    //
    //   markVerified    — `connect()` returned success. Stamps the time,
    //                     clears any stale error. Sidebar shows the device
    //                     as ready; panel shows "Last verified now".
    //   markFailed      — `connect()` or a pull threw. Clears the stamp,
    //                     records the humanized message. Sidebar surfaces
    //                     this as `authFailed` so a subsequent session sees
    //                     "Setup" badge instead of a stale "ready".
    //   clearVerified   — Sign Out. Clears both fields; user is explicitly
    //                     removing credentials and we shouldn't carry over
    //                     an error from a previous session.

    public func markVerified(deviceId: String, at date: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        guard let idx = _devices.firstIndex(where: { $0.id == deviceId }) else { return }
        var device = _devices[idx]
        device.lastVerifiedAt = date
        device.lastAuthError = nil
        _devices[idx] = device
        try? store.save(device)
    }

    public func markFailed(deviceId: String, error message: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let idx = _devices.firstIndex(where: { $0.id == deviceId }) else { return }
        var device = _devices[idx]
        device.lastVerifiedAt = nil
        device.lastAuthError = message
        _devices[idx] = device
        try? store.save(device)
    }

    public func clearVerified(deviceId: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let idx = _devices.firstIndex(where: { $0.id == deviceId }) else { return }
        var device = _devices[idx]
        device.lastVerifiedAt = nil
        device.lastAuthError = nil
        _devices[idx] = device
        try? store.save(device)
    }

    // MARK: - Param Resolution

    /// Resolve params for execution: override > device config > Keychain > schema default.
    public func resolveParams(device: Device, schema: [ParamSpec],
                               overrides: [String: String] = [:]) -> [String: String] {
        var resolved: [String: String] = [:]
        for spec in schema {
            if let override = overrides[spec.key] {
                resolved[spec.key] = override
            } else if let configVal = device.config[spec.key] {
                resolved[spec.key] = configVal
            } else if spec.type == .keychain, let value = getKeychain(deviceId: device.id, paramKey: spec.key) {
                resolved[spec.key] = value
            } else if let defaultVal = spec.defaultValue {
                resolved[spec.key] = defaultVal
            }
        }
        return resolved
    }

    /// Resolve params for status/display only: never reads keychain secret values.
    /// Keychain-typed params are stubbed with a non-empty placeholder if present,
    /// or omitted if absent. Use this for discovery, readiness checks, and schema
    /// resolution — anywhere the caller only needs presence, not the secret itself.
    public func resolveParamsForStatus(device: Device, schema: [ParamSpec]) -> [String: String] {
        var resolved: [String: String] = [:]
        for spec in schema {
            if spec.type == .keychain {
                if keychainParamExists(deviceId: device.id, paramKey: spec.key) {
                    resolved[spec.key] = Self.keychainPresencePlaceholder
                }
            } else if let configVal = device.config[spec.key] {
                resolved[spec.key] = configVal
            } else if let defaultVal = spec.defaultValue {
                resolved[spec.key] = defaultVal
            }
        }
        return resolved
    }

    /// Sentinel returned by resolveParamsForStatus for present-but-unread
    /// keychain params. Non-empty so `params[x].isEmpty` behaves like a real value.
    static let keychainPresencePlaceholder = "<keychain>"

    // MARK: - Validation

    /// Wrapper so [DeviceError] can be used as a Result failure type.
    public struct ValidationErrors: Error {
        public let messages: [DeviceError]
    }

    /// Resolved device context — carries everything needed to execute.
    public struct ResolvedDevice: @unchecked Sendable {
        public let device: Device
        public let manifest: ToolManifest
        public let params: [String: String]
        public let instance: any Tool
    }

    /// Resolve a device for execution: look up device, manifest, params, instance.
    /// Returns errors for missing device/tool/required params and check() failures.
    /// Does NOT call connect() — caller decides when to connect.
    @MainActor
    public func resolveDevice(id: String) -> Result<ResolvedDevice, ValidationErrors> {
        guard let device = get(id: id) else {
            return .failure(ValidationErrors(messages: [DeviceError(category: .resourceGone, message: "Device '\(id)' not found. Run 'goodboy devices' to see available devices.")]))
        }

        guard let manifest = registry.manifests.first(where: { $0.id == device.tool }) else {
            return .failure(ValidationErrors(messages: [DeviceError(category: .resourceGone, message: "Tool '\(device.tool)' not registered. Run 'goodboy devices' to check.")]))
        }

        let resolved = resolveParams(device: device, schema: manifest.paramSchema)

        var errors: [DeviceError] = []

        for spec in manifest.paramSchema where spec.required {
            if resolved[spec.key] == nil {
                errors.append(DeviceError(category: .missingParam, message: "Missing required param '\(spec.label)'. Run device setup to configure it.", action: "Configure \(spec.label)"))
            }
        }

        guard let instance = registry.instantiate(id: device.tool) else {
            errors.append(DeviceError(category: .resourceGone, message: "Could not instantiate tool '\(device.tool)'. Check your installation."))
            return .failure(ValidationErrors(messages: errors))
        }

        guard errors.isEmpty else { return .failure(ValidationErrors(messages: errors)) }

        // Run check() — catches notInstalled, notRunning, resourceGone, authFailed.
        // authFailed from check() is NOT blocking — connect()/execute() can auto-login.
        let checkErrors = instance.check(params: resolved)
        let blocking = checkErrors.filter { $0.category != .authFailed }
        errors.append(contentsOf: blocking)

        guard errors.isEmpty else { return .failure(ValidationErrors(messages: errors)) }

        return .success(ResolvedDevice(device: device, manifest: manifest, params: resolved, instance: instance))
    }

    /// Build resolvedKeychain map for a device — only keychain params.
    /// Attributes-only existence check; never reads secret payloads.
    public func buildResolvedKeychain(device: Device, schema: [ParamSpec]) -> [String: Bool] {
        let keychainParams = schema.filter { $0.type == .keychain }
        return Dictionary(uniqueKeysWithValues:
            keychainParams.map { ($0.key, keychainParamExists(deviceId: device.id, paramKey: $0.key)) }
        )
    }

    // MARK: - Keychain Dev Operations

    public struct AutoSeeded: Encodable, Sendable {
        public let deviceId: String
        public let paramKey: String
        public let message: String
        public let alreadyCached: Bool
    }

    public struct NeedsInput: Encodable, Sendable {
        public let deviceId: String
        public let paramKey: String
        public let label: String
        public let description: String
        public let required: Bool
    }

    public struct SeedResult: Encodable, Sendable {
        public let success: Bool
        public let autoSeeded: [AutoSeeded]
        public let needsInput: [NeedsInput]
        public let errors: [AutoSeeded]
    }

    public struct KeychainStatus: Encodable, Sendable {
        public struct ServiceStatus: Encodable, Sendable {
            public let service: String
            public let accounts: [String]
        }
        public let services: [ServiceStatus]
    }

    public struct KeychainWipeResult: Encodable, Sendable {
        public let wiped: [String]
        public let message: String
    }

    public func keychainStatus() -> KeychainStatus {
        let deviceAccounts = keychain.listAccounts()
        let appAccounts = Keychain.app.listAccounts()
        return KeychainStatus(services: [
            .init(service: "app.gboy.goodboy.devices", accounts: deviceAccounts),
            .init(service: "app.gboy.goodboy", accounts: appAccounts),
        ])
    }

    public func wipeKeychain(target: String? = nil) -> KeychainWipeResult {
        switch target {
        case "devices":
            let accounts = keychain.listAccounts()
            keychain.clear()
            return KeychainWipeResult(
                wiped: accounts.isEmpty ? [] : ["devices (\(accounts.count) entries)"],
                message: accounts.isEmpty ? "No device entries to wipe." : "Wiped \(accounts.count) device entries."
            )
        case "app":
            let accounts = Keychain.app.listAccounts()
            Keychain.app.clear()
            return KeychainWipeResult(
                wiped: accounts.isEmpty ? [] : ["app (\(accounts.count) entries)"],
                message: accounts.isEmpty ? "No app entries to wipe." : "Wiped \(accounts.count) app entries."
            )
        case nil:
            var wiped: [String] = []
            let deviceAccounts = keychain.listAccounts()
            if !deviceAccounts.isEmpty {
                keychain.clear()
                wiped.append("devices (\(deviceAccounts.count) entries)")
            }
            let appAccounts = Keychain.app.listAccounts()
            if !appAccounts.isEmpty {
                Keychain.app.clear()
                wiped.append("app (\(appAccounts.count) entries)")
            }
            let msg = wiped.isEmpty ? "Nothing to wipe." : "Wiped: \(wiped.joined(separator: ", "))"
            return KeychainWipeResult(wiped: wiped, message: msg)
        default:
            return KeychainWipeResult(wiped: [], message: "Unknown target: \(target!). Use 'devices' or 'app'.")
        }
    }

    /// Auto-seed browser keys and scan all devices for missing keychain params.
    @MainActor
    public func seedKeychain(
        targetDeviceId: String? = nil,
        extractBrowserKey: ((_ chromeDir: String) throws -> String)? = nil
    ) -> SeedResult {
        reload()

        let chromeToolId = "chrome"
        let allDevices = devices
        let devicesToScan: [Device]

        if let targetId = targetDeviceId {
            guard let device = allDevices.first(where: { $0.id == targetId }) else {
                return SeedResult(success: false, autoSeeded: [], needsInput: [], errors: [
                    AutoSeeded(deviceId: targetId, paramKey: "", message: "Device '\(targetId)' not found.", alreadyCached: false)
                ])
            }
            devicesToScan = [device]
        } else {
            devicesToScan = allDevices
        }

        var autoSeeded: [AutoSeeded] = []
        var needsInput: [NeedsInput] = []
        var errors: [AutoSeeded] = []
        var seenParams: Set<String> = []

        for device in devicesToScan {
            guard let manifest = registry.manifests.first(where: { $0.id == device.tool }) else { continue }
            let keychainParams = manifest.paramSchema.filter { $0.type == .keychain }

            for spec in keychainParams {
                let dedupKey = "\(device.id)|\(spec.key)"

                if keychainParamExists(deviceId: device.id, paramKey: spec.key) {
                    if device.tool == chromeToolId && spec.key == "safeStorageKey" {
                        if seenParams.insert(dedupKey).inserted {
                            autoSeeded.append(AutoSeeded(
                                deviceId: device.id, paramKey: spec.key,
                                message: "Already seeded.", alreadyCached: true
                            ))
                        }
                    }
                    continue
                }

                guard seenParams.insert(dedupKey).inserted else { continue }

                if device.tool == chromeToolId && spec.key == "safeStorageKey",
                   let extract = extractBrowserKey {
                    let chromeDir = device.config["chromeDir"] ?? ""
                    do {
                        let keyB64 = try extract(chromeDir)
                        try setKeychain(deviceId: device.id, paramKey: spec.key, value: keyB64)
                        autoSeeded.append(AutoSeeded(
                            deviceId: device.id, paramKey: spec.key,
                            message: "Browser key extracted and stored.", alreadyCached: false
                        ))
                    } catch {
                        errors.append(AutoSeeded(
                            deviceId: device.id, paramKey: spec.key,
                            message: error.localizedDescription, alreadyCached: false
                        ))
                    }
                } else {
                    needsInput.append(NeedsInput(
                        deviceId: device.id, paramKey: spec.key,
                        label: spec.label, description: spec.description,
                        required: spec.required
                    ))
                }
            }
        }

        return SeedResult(success: errors.isEmpty, autoSeeded: autoSeeded, needsInput: needsInput, errors: errors)
    }

    // MARK: - Bootstrap

    /// Pre-built devices that ship with Goodboy (zero-config drivers only).
    private static let prebuiltToolIds: Set<String> = ["icloud"]

    /// Create pre-built devices on first launch.
    @MainActor
    public func bootstrapDefaults() {
        for manifest in registry.manifests {
            guard Self.prebuiltToolIds.contains(manifest.id) else { continue }
            guard devices(forTool: manifest.id).isEmpty else { continue }
            let device = Device(
                id: "\(manifest.id)-default",
                tool: manifest.id,
                slug: "default",
                name: manifest.name,
                canRead: true,
                canWrite: true,
                createdAt: Date()
            )
            try? save(device)
        }
    }
}
