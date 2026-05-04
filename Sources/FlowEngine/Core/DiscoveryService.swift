// Device lifecycle: discovers new devices from tool suggestions,
// detects changes via file fingerprints, and provides check()-based status.
//
// discover() scans the machine — called once on launch.
// deviceStatus() calls check() on the tool — called per device on demand.

import Foundation
import os.log

// MARK: - Result Types

/// Runtime status for a device (not persisted — computed on each check).
public struct DeviceRuntimeStatus: Sendable {
    public let ready: Bool
    public let changed: Bool
    public let missing: [String]    // e.g. ["dbPassword"] — param keys, not labels
    public let errors: [DeviceError]
    public let resolvedKeychain: [String: Bool]  // e.g. ["dbPassword": true, "keyFile": false]

    public init(ready: Bool, changed: Bool, missing: [String], errors: [DeviceError], resolvedKeychain: [String: Bool]) {
        self.ready = ready
        self.changed = changed
        self.missing = missing
        self.errors = errors
        self.resolvedKeychain = resolvedKeychain
    }
}

/// A device paired with its runtime status. This is what consumers use.
public struct DeviceInfo: Sendable, Identifiable {
    public var id: String { device.id }
    public let device: Device
    public let status: DeviceRuntimeStatus

    public init(device: Device, status: DeviceRuntimeStatus) {
        self.device = device
        self.status = status
    }

    /// Flat dictionary for JSON serialization — shared by MCP and FM tool.
    public func _get() -> [String: Any] {
        var d: [String: Any] = [
            "id": device.id,
            "name": device.name,
            "ready": status.ready,
            "changed": status.changed,
        ]
        if let count = device.credentialCount { d["credentialCount"] = count }
        if !status.missing.isEmpty { d["missing"] = status.missing }
        if !status.errors.isEmpty {
            d["errors"] = status.errors.map { ["category": $0.category.rawValue, "message": $0.message] }
        }
        return d
    }
}

// MARK: - DiscoveryService

public enum DiscoveryService {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "DiscoveryService")

    // MARK: - Discovery Result

    public struct DiscoveryResult: Sendable {
        public let created: [String]
        public let removed: [String]
        public let changed: Set<String>
    }

    // MARK: - Discover

    /// Scan the machine: create/delete/update device rows in SQLite.
    /// No availability checks — just makes sure the device table is current.
    /// Call once on app launch, or when the user triggers a rescan.
    @MainActor
    public static func discover() -> DiscoveryResult {
        DeviceService.shared.reload()

        var removed: [String] = []
        var created: [String] = []
        var changedIds = Set<String>()
        var metadataRefreshedIds = Set<String>()

        // --- Load & Sanitize ---
        for device in DeviceService.shared.devices {
            guard ToolRegistry.shared.manifests.contains(where: { $0.id == device.tool }) else {
                do {
                    try DeviceService.shared.delete(id: device.id)
                } catch {
                    log.error("Failed to delete orphaned device '\(device.id)': \(error.localizedDescription)")
                }
                removed.append(device.id)
                continue
            }
        }

        if !removed.isEmpty { DeviceService.shared.reload() }

        // --- Change Detection ---
        for device in DeviceService.shared.devices {
            guard let manifest = ToolRegistry.shared.manifests.first(where: { $0.id == device.tool }),
                  let instance = ToolRegistry.shared.instantiate(id: manifest.id) else { continue }
            let resolved = DeviceService.shared.resolveParamsForStatus(device: device, schema: manifest.paramSchema)
            let files = instance.watchedFiles(params: resolved)
            guard !files.isEmpty else { continue }
            if fileFingerprint(files) != device.fingerprint {
                changedIds.insert(device.id)
            }
        }

        // --- Discover new devices ---
        for manifest in ToolRegistry.shared.manifests {
            guard let instance = ToolRegistry.shared.instantiate(id: manifest.id) else { continue }
            let suggestions = instance.suggestDeviceConfigs()
            guard !suggestions.isEmpty else { continue }

            let existingDevices = DeviceService.shared.devices(forTool: manifest.id)
            var coveredIndices = Set<Int>()
            var matchedDeviceIds = Set<String>()

            for device in existingDevices {
                let normalizedConfig = instance.normalizeConfig(device.config)
                if let matchIdx = suggestions.firstIndex(where: { config in
                    config.filter { !$0.key.hasPrefix("_") }
                        .allSatisfy { key, value in normalizedConfig[key] == value }
                }) {
                    coveredIndices.insert(matchIdx)
                    matchedDeviceIds.insert(device.id)

                    // Refresh display metadata from the live suggestion.
                    // The non-`_` config keys are the device's identity (used for matching);
                    // `_`-prefixed keys (`_name`, `_profileName`, `_canRead`, `_canWrite`) are
                    // recomputed each scan so that e.g. a Chrome profile rename is reflected
                    // in the UI without losing the device row.
                    let raw = suggestions[matchIdx]
                    let liveConfig = raw.filter { !$0.key.hasPrefix("_") }
                    let liveDeviceName = raw["_name"] ?? manifest.name
                    let (liveTitle, liveSubtitle) = DeviceDisplayName.compute(
                        tool: manifest.id, slug: device.slug,
                        deviceName: liveDeviceName, config: liveConfig
                    )
                    let liveProfileName = raw["_profileName"]
                    let liveCanRead = raw["_canRead"] == "true" || instance.canRead(slug: device.slug)
                    let liveCanWrite = raw["_canWrite"] == "true" || instance.canWrite(slug: device.slug)

                    if device.name != liveTitle
                        || device.subtitle != liveSubtitle
                        || device.profileName != liveProfileName
                        || device.canRead != liveCanRead
                        || device.canWrite != liveCanWrite {
                        var updated = device
                        updated.name = liveTitle
                        updated.subtitle = liveSubtitle
                        updated.profileName = liveProfileName
                        updated.canRead = liveCanRead
                        updated.canWrite = liveCanWrite
                        do {
                            try DeviceService.shared.save(updated)
                            metadataRefreshedIds.insert(device.id)
                        } catch {
                            log.error("Failed to refresh display metadata for '\(device.id)': \(error.localizedDescription)")
                        }
                    }
                }
            }

            for device in existingDevices where !matchedDeviceIds.contains(device.id) {
                do {
                    try DeviceService.shared.delete(id: device.id)
                } catch {
                    log.error("Failed to delete unmatched device '\(device.id)': \(error.localizedDescription)")
                }
                removed.append(device.id)
            }

            for (idx, rawConfig) in suggestions.enumerated() where !coveredIndices.contains(idx) {
                let deviceName = rawConfig["_name"] ?? manifest.name
                let config = rawConfig.filter { !$0.key.hasPrefix("_") }

                // Slug allocation: preferred `_slug` if free → unused slug-pool entry → `default-N`.
                // Falling through on collision (instead of skipping) is what catches the case where
                // a newly-detected resource sorts before an already-bound one and would otherwise
                // collide on the index-derived slug — e.g. a second KeePassXC db that lands at
                // index 0 and tries to claim "default" from the existing device.
                let existingSlugs = Set(DeviceService.shared.devices(forTool: manifest.id).map(\.slug))
                let slug: String
                if let preferred = rawConfig["_slug"], !preferred.isEmpty, !existingSlugs.contains(preferred) {
                    slug = preferred
                } else if let poolSlug = manifest.slugPool.map(\.slug).first(where: { !existingSlugs.contains($0) }) {
                    slug = poolSlug
                } else {
                    var n = 2
                    while existingSlugs.contains("default-\(n)") { n += 1 }
                    slug = "default-\(n)"
                }

                let deviceId = "\(manifest.id)-\(slug)"

                let fingerprint = fileFingerprint(instance.watchedFiles(params: config))
                let count = instance.credentialCount(params: config)

                let canRead = rawConfig["_canRead"] == "true" || instance.canRead(slug: slug)
                let canWrite = rawConfig["_canWrite"] == "true" || instance.canWrite(slug: slug)

                let (title, subtitle) = DeviceDisplayName.compute(
                    tool: manifest.id, slug: slug,
                    deviceName: deviceName, config: config
                )
                let category = DeviceDisplayName.category(tool: manifest.id)
                let profileName = rawConfig["_profileName"]
                let autoPinTools: Set<String> = ["icloud"]

                let device = Device(
                    id: deviceId,
                    tool: manifest.id,
                    slug: slug,
                    name: title,
                    canRead: canRead,
                    canWrite: canWrite,
                    config: config,
                    category: category,
                    subtitle: subtitle,
                    profileName: profileName,
                    pinned: autoPinTools.contains(manifest.id),
                    createdAt: Date(),
                    fingerprint: fingerprint,
                    credentialCount: count
                )
                do {
                    try DeviceService.shared.save(device)
                } catch {
                    log.error("Failed to save discovered device '\(deviceId)': \(error.localizedDescription)")
                }
                created.append(deviceId)
            }
        }

        // --- Upsert changed ---
        var reallyChanged = Set<String>()
        for id in changedIds {
            guard var device = DeviceService.shared.get(id: id),
                  let manifest = ToolRegistry.shared.manifests.first(where: { $0.id == device.tool }),
                  let instance = ToolRegistry.shared.instantiate(id: manifest.id) else { continue }
            let resolved = DeviceService.shared.resolveParamsForStatus(device: device, schema: manifest.paramSchema)
            let newFingerprint = fileFingerprint(instance.watchedFiles(params: resolved))
            let newCount = instance.credentialCount(params: resolved)

            if newCount != device.credentialCount || newFingerprint != device.fingerprint {
                reallyChanged.insert(id)
            }

            device.fingerprint = newFingerprint
            if newCount != nil { device.credentialCount = newCount }
            do {
                try DeviceService.shared.save(device)
            } catch {
                log.error("Failed to save updated device '\(id)': \(error.localizedDescription)")
            }
        }

        reallyChanged.formUnion(metadataRefreshedIds)

        if !reallyChanged.isEmpty || !created.isEmpty { DeviceService.shared.reload() }

        return DiscoveryResult(created: created, removed: removed, changed: reallyChanged)
    }

    // MARK: - Device Status (per-device — calls check())

    /// Lightweight availability check for a single device.
    /// Instantiates the tool, calls check(params:), resolves params.
    /// Does NOT run discovery or modify SQLite.
    @MainActor
    public static func deviceStatus(id: String) -> DeviceRuntimeStatus? {
        guard let device = DeviceService.shared.get(id: id) else { return nil }
        return deviceStatus(for: device)
    }

    /// Availability check from a Device value.
    ///
    /// Never reads keychain secret values — uses attributes-only existence
    /// checks so `goodboy_devices` / discovery never triggers macOS ACL prompts.
    /// Real secret reads only happen when the user explicitly asks for a live
    /// action (validate, connect, run).
    @MainActor
    public static func deviceStatus(for device: Device) -> DeviceRuntimeStatus? {
        guard let manifest = ToolRegistry.shared.manifests.first(where: { $0.id == device.tool }),
              let instance = ToolRegistry.shared.instantiate(id: manifest.id) else { return nil }

        let resolved = DeviceService.shared.resolveParamsForStatus(device: device, schema: manifest.paramSchema)
        let missingParams = manifest.paramSchema.filter { $0.required && resolved[$0.key] == nil }.map(\.key)
        let resolvedKeychain = DeviceService.shared.buildResolvedKeychain(device: device, schema: manifest.paramSchema)

        // Call check() unconditionally. `resolved` carries placeholders for
        // present keychain params (no secret values are read). Each tool's
        // check() returns its precondition errors (CLI installed, app present,
        // resource reachable) before any cred-using path runs — gating the
        // entire call on stored-cred presence hides those preconditions until
        // the user submits the form, which is where the missing install link
        // came from. Eventually preconditions move to a dedicated
        // protocolAvailability() method per the wider state-model rework.
        let errors = instance.check(params: resolved)

        return DeviceRuntimeStatus(
            ready: missingParams.isEmpty && errors.isEmpty,
            changed: false,
            missing: missingParams,
            errors: errors,
            resolvedKeychain: resolvedKeychain
        )
    }

    // MARK: - Private Helpers

    private static func fileFingerprint(_ paths: [String]) -> String? {
        let fm = FileManager.default
        var parts: [String] = []
        for path in paths.sorted() {
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let mtime = attrs[.modificationDate] as? Date else { continue }
            parts.append("\(mtime.timeIntervalSince1970)")
        }
        return parts.isEmpty ? nil : parts.joined(separator: ":")
    }

    // MARK: - Device Query

    /// Filter devices by tool and slug exclusions. Reads from DB — no discover.
    @MainActor
    public static func findDevices(
        toolId: String,
        excludeSlugs: Set<String> = []
    ) -> (ready: [DeviceInfo], unready: [DeviceInfo]) {
        let all = devicesFromDB()
        let matched = all.filter {
            $0.device.tool == toolId
            && !excludeSlugs.contains($0.device.slug)
        }
        return splitReadyUnready(matched)
    }

    /// All source or destination devices. Reads from DB — no discover.
    @MainActor
    public static func findDevices(
        sources: Bool
    ) -> (ready: [DeviceInfo], unready: [DeviceInfo]) {
        let all = devicesFromDB()
        let matched = all.filter { sources ? $0.device.canRead : $0.device.canWrite }
        return splitReadyUnready(matched)
    }

    @MainActor
    private static func devicesFromDB() -> [DeviceInfo] {
        DeviceService.shared.reload()
        return DeviceService.shared.devices.compactMap { device in
            guard let status = deviceStatus(for: device) else { return nil }
            return DeviceInfo(device: device, status: status)
        }
    }

    private static func splitReadyUnready(_ devices: [DeviceInfo]) -> (ready: [DeviceInfo], unready: [DeviceInfo]) {
        let ready = devices.filter { $0.status.ready }
            .sorted { ($0.device.credentialCount ?? 0) > ($1.device.credentialCount ?? 0) }
        let unready = devices.filter { !$0.status.ready }
        return (ready, unready)
    }
}
