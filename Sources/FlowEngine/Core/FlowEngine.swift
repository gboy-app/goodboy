// Executes credential flows.
// Agent fires, engine owns. Results via FlowEvent.
//
// Usage:
//    FlowEngine.shared.run("chrome-default")
//    FlowEngine.shared.run("chrome-default", "json-default")

import Foundation
import os.log

// MARK: - FlowEvent

public enum FlowEvent: Sendable {
    case started(flowId: String)
    case stepComplete(flowId: String, deviceId: String, result: ToolResult)
    case complete(flowId: String, preflight: PreflightReport?)
    case failed(flowId: String, deviceId: String?, error: String)
}

// MARK: - FlowState

public enum FlowState: String, Sendable {
    case idle
    case running
    case complete
    case failed
}

// MARK: - FlowEngine

@MainActor
public final class FlowEngine: ObservableObject {
    public static let shared = FlowEngine()

    private let log = Logger(subsystem: "app.gboy.goodboy", category: "FlowEngine")
    private let deviceService: DeviceService
    private let registry: ToolRegistry

    @Published public private(set) var activeFlowId: String?
    @Published public private(set) var state: FlowState = .idle

    public var onEvent: ((FlowEvent) -> Void)?

    private init() {
        self.deviceService = .shared
        self.registry = .shared
    }

    /// Testable init: inject DeviceService and optional ToolRegistry.
    public init(deviceService: DeviceService, registry: ToolRegistry = .shared) {
        self.deviceService = deviceService
        self.registry = registry
    }

    private func emit(_ event: FlowEvent) {
        if Thread.isMainThread {
            onEvent?(event)
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.onEvent?(event)
            }
        }
    }

    // MARK: - Run

    /// Run a flow with an ordered array of device IDs.
    /// Each device is executed in order. Action (read/write) inferred from device capabilities.
    ///
    /// SecuredBox lifecycle:
    /// - Complete flow (source + dest, 2+ devices): clear before source, clear after last dest.
    /// - Single source: loads into SecuredBox (user picks dest later).
    /// - Single dest: never clears SecuredBox.
    public func run(_ deviceIds: [String], actionOverride: ToolAction? = nil, securedBox: SecuredBox = .shared, extraParams: [String: String] = [:]) {
        guard !deviceIds.isEmpty else {
            emit(.failed(flowId: "", deviceId: nil,
                         error: "No device IDs provided. Pass at least one device ID to run."))
            return
        }

        guard state != .running else {
            emit(.failed(flowId: "", deviceId: nil,
                         error: "A flow is already running. Wait for it to complete before starting another."))
            return
        }

        let isCompleteFlow = deviceIds.count >= 2

        let flowId = UUID().uuidString
        self.activeFlowId = flowId
        self.state = .running
        emit(.started(flowId: flowId))

        Task {
            if isCompleteFlow {
                securedBox.clear()
            }

            var preflightReport: PreflightReport? = nil

            for (index, deviceId) in deviceIds.enumerated() {
                // Determine action: explicit override > device capabilities > position.
                let intendedAction: ToolAction
                let isDest: Bool
                if let override = actionOverride {
                    intendedAction = override
                    isDest = override == .write
                } else if let device = deviceService.get(id: deviceId) {
                    if device.canWrite && !device.canRead {
                        intendedAction = .write
                        isDest = true
                    } else if device.canRead && !device.canWrite {
                        intendedAction = .read
                        isDest = false
                    } else {
                        // Bidirectional: last in a multi-device flow = write
                        let isLast = isCompleteFlow && index == deviceIds.count - 1
                        intendedAction = isLast ? .write : .read
                        isDest = isLast
                    }
                } else {
                    let isLast = isCompleteFlow && index == deviceIds.count - 1
                    intendedAction = isLast ? .write : .read
                    isDest = isLast
                }

                // Before dest, compute preflight
                if isDest {
                    preflightReport = preflight(destDeviceId: deviceId, securedBox: securedBox)
                    if let destFields = resolveDestSchema(for: deviceId) {
                        // Log fields that will be lost in transfer (e.g. OTP, passkeys → Chrome)
                        let destKeySet = Set(destFields.map(\.key))
                        let fieldNames: [String: String] = [
                            "otpAuth": "OTP",
                            "passkey_rpId": "passkey",
                            "passkey_credentialId": "passkey",
                            "passkey_userHandle": "passkey",
                            "passkey_userName": "passkey",
                            "passkey_userDisplayName": "passkey",
                            "passkey_key": "passkey",
                        ]
                        var countsByLabel: [String: Int] = [:]
                        for item in securedBox.items {
                            var seenLabelsForItem = Set<String>()
                            for key in item.presentKeys.subtracting(destKeySet) {
                                if key == "sourceDeviceId" || key == "accountEmail" { continue }
                                let label = fieldNames[key] ?? key
                                if seenLabelsForItem.insert(label).inserted {
                                    countsByLabel[label, default: 0] += 1
                                }
                            }
                        }
                        if !countsByLabel.isEmpty {
                            let destName = deviceService.get(id: deviceId)?.name ?? deviceId
                            let parts = countsByLabel.sorted(by: { $0.value > $1.value }).map { label, count -> String in
                                return "\(label) (\(count) \(count == 1 ? "entry" : "entries"))"
                            }
                            let msg = "\(destName) doesn't support: \(parts.joined(separator: ", ")) — these fields won't transfer"
                            log.info("\(msg, privacy: .private)")
                            emit(.stepComplete(flowId: flowId, deviceId: deviceId, result: .success(
                                count: 0,
                                message: msg
                            )))
                        }
                    }
                }

                guard let result = await executeDevice(deviceId, action: intendedAction, securedBox: securedBox, flowId: flowId, extraParams: extraParams) else {
                    return
                }
                emit(.stepComplete(flowId: flowId, deviceId: deviceId, result: result))
            }

            if isCompleteFlow {
                securedBox.clear()
            }

            self.state = .complete
            self.activeFlowId = nil
            emit(.complete(flowId: flowId, preflight: preflightReport))
        }
    }

    /// Convenience: single device — action inferred from capabilities.
    public func run(_ deviceId: String, securedBox: SecuredBox = .shared) {
        run([deviceId], securedBox: securedBox)
    }

    /// Explicit action: caller knows the intent (e.g. pushToDestination → .write).
    public func run(_ deviceId: String, action: ToolAction, securedBox: SecuredBox = .shared, extraParams: [String: String] = [:]) {
        run([deviceId], actionOverride: action, securedBox: securedBox, extraParams: extraParams)
    }

    /// Convenience: source → dest.
    public func run(_ source: String, _ dest: String, securedBox: SecuredBox = .shared) {
        run([source, dest], actionOverride: nil, securedBox: securedBox)
    }

    // MARK: - Execute Device

    private func executeDevice(
        _ deviceId: String,
        action: ToolAction,
        securedBox: SecuredBox,
        flowId: String,
        extraParams: [String: String] = [:]
    ) async -> ToolResult? {
        let resolved: DeviceService.ResolvedDevice
        switch deviceService.resolveDevice(id: deviceId) {
        case .success(let r):
            resolved = r
        case .failure(let errors):
            let message = errors.messages.map(\.message).joined(separator: " ")
            log.error("Validation failed for \(deviceId): \(message)")
            failWithMark(flowId: flowId, deviceId: deviceId, error: message)
            return nil
        }

        // Validate device supports the intended action
        if action == .read && !resolved.device.canRead {
            let error = "'\(resolved.device.name)' (\(deviceId)) cannot read. Check device capabilities or use a different source."
            log.error("\(error)")
            failWithMark(flowId: flowId, deviceId: deviceId, error: error)
            return nil
        }
        if action == .write && !resolved.device.canWrite {
            let error = "'\(resolved.device.name)' (\(deviceId)) cannot write. Check device capabilities or use a different destination."
            log.error("\(error)")
            failWithMark(flowId: flowId, deviceId: deviceId, error: error)
            return nil
        }

        // Availability gate: probe preconditions before spending a connect().
        // Surfaces notInstalled / notRunning / resourceGone with the tool's
        // own category + message instead of whatever raw string connect() would
        // throw. authFailed from check() is deliberately ignored here — connect()
        // is the real auth test.
        if let avail = DiscoveryService.deviceStatus(for: resolved.device) {
            if !avail.missing.isEmpty {
                let error = "'\(resolved.device.name)' is missing required config: \(avail.missing.joined(separator: ", "))."
                log.error("\(error)")
                failWithMark(flowId: flowId, deviceId: deviceId, error: error)
                return nil
            }
            if let precondition = avail.errors.first(where: {
                [.notInstalled, .notRunning, .resourceGone].contains($0.category)
            }) {
                log.error("Precondition failed for \(deviceId): \(precondition.message)")
                failWithMark(flowId: flowId, deviceId: deviceId, error: precondition.message)
                return nil
            }
        }

        let params = resolved.params.merging(extraParams) { _, new in new }

        // connect() — real auth test before execute
        // Run on a non-cooperative thread to avoid blocking the main actor
        // while waiting for subprocess I/O (e.g. Bitwarden CLI calls).
        let capturedInstance = resolved.instance
        let connectError: String? = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try capturedInstance.connect(params: params)
                    continuation.resume(returning: nil)
                } catch {
                    continuation.resume(returning: error.localizedDescription)
                }
            }
        }
        if let error = connectError {
            log.error("Connect failed for \(deviceId): \(error)")
            failWithMark(flowId: flowId, deviceId: deviceId, error: error)
            return nil
        }

        log.info("Executing \(deviceId) action=\(action.rawValue)")
        do {
            // Reads use a local box: stamp locally, then merge into the shared box.
            // This avoids stampSource races when multiple flows pull concurrently.
            let targetBox: SecuredBox
            if action == .read {
                targetBox = SecuredBox(forTesting: true)
            } else {
                targetBox = securedBox
            }

            let capturedParams = params
            let result = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ToolResult, Error>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    Task {
                        do {
                            let r = try await capturedInstance.execute(action: action, params: capturedParams, securedBox: targetBox)
                            continuation.resume(returning: r)
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                }
            }

            if !result.success {
                log.error("Step failed for \(deviceId): \(result.error ?? "unknown")")
                failWithMark(flowId: flowId, deviceId: deviceId,
                             error: result.error ?? "Execution failed for '\(deviceId)'. Check logs for details.")
                return nil
            }

            if action == .read {
                targetBox.stampSource(deviceId)
                securedBox.append(targetBox.items)
            }

            // Step succeeded: stamp lastVerifiedAt, clear lastAuthError.
            // Makes every caller (UI, App MCP, Standalone MCP) get writeback
            // for free — not just the SwiftUI FlowEvent listener.
            deviceService.markVerified(deviceId: deviceId)

            return result
        } catch {
            log.error("Step threw for \(deviceId): \(error.localizedDescription)")
            failWithMark(flowId: flowId, deviceId: deviceId,
                         error: error.localizedDescription)
            return nil
        }
    }

    // MARK: - Pre-Flight

    public func preflight(destDeviceId: String, securedBox: SecuredBox = .shared) -> PreflightReport? {
        guard let destFields = resolveDestSchema(for: destDeviceId) else { return nil }

        let items = securedBox.items
        guard !items.isEmpty else {
            return PreflightReport(groups: [])
        }

        var grouped: [String: [BoxItem]] = [:]
        for item in items {
            let key = item.sourceDeviceId ?? "_unknown"
            grouped[key, default: []].append(item)
        }

        var groups: [PreflightGroup] = []

        for (sourceId, groupItems) in grouped {
            let sampleMapping = groupItems[0].mapping(to: destFields)

            var transferCount = 0
            var skipCount = 0
            var skipReasonCounts: [String: Int] = [:]

            for item in groupItems {
                let result = item.mapping(to: destFields)
                if let reason = result.skipReason {
                    skipCount += 1
                    skipReasonCounts[reason, default: 0] += 1
                } else {
                    transferCount += 1
                }
            }

            let skipReasons = skipReasonCounts.map { "\($0.value) items: \($0.key)" }

            groups.append(PreflightGroup(
                sourceDeviceId: sourceId == "_unknown" ? nil : sourceId,
                itemCount: groupItems.count,
                mapping: sampleMapping,
                transferCount: transferCount,
                skipCount: skipCount,
                skipReasons: skipReasons
            ))
        }

        return PreflightReport(groups: groups)
    }

    /// Resolve dest schema using this engine's deviceService.
    private func resolveDestSchema(for deviceId: String) -> [DataSchemaField]? {
        guard let device = deviceService.get(id: deviceId),
              let manifest = registry.manifests.first(where: { $0.id == device.tool }),
              let instance = registry.instantiate(id: manifest.id) else {
            return nil
        }
        let resolved = deviceService.resolveParams(device: device, schema: manifest.paramSchema)
        return instance.dataSchema(params: resolved)
    }

    private func failFlow(flowId: String, deviceId: String, error: String) {
        guard state == .running else { return } // prevent double-fire from concurrent sources
        emit(.failed(flowId: flowId, deviceId: deviceId, error: error))
        self.state = .failed
        self.activeFlowId = nil
    }

    /// Stamp the device as failed, then fail the flow. Writeback before the
    /// event so any listener that re-reads SQLite on .failed sees the row
    /// already updated. Replaces the UI-side `looksLikeAuthFailure` heuristic:
    /// every step failure — auth, CLI crash, parse error, network, whatever —
    /// flips the device to `lastAuthError` set. The field is named "auth" but
    /// the semantics are "last attempt didn't work."
    private func failWithMark(flowId: String, deviceId: String, error: String) {
        deviceService.markFailed(deviceId: deviceId, error: error)
        failFlow(flowId: flowId, deviceId: deviceId, error: error)
    }
}
