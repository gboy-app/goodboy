// MCP handlers for flow execution: `goodboy_run` and `goodboy_flows`.

import Foundation
import MCP
import FlowEngine

func handleRun(_ arguments: [String: Value]?) async throws -> CallTool.Result {
    let source = arguments?["source"]?.stringValue
    let dest = arguments?["dest"]?.stringValue

    guard source != nil || dest != nil else {
        throw MCPError.invalidParams("Pass at least one of 'source' or 'dest'.")
    }

    // Reject devices whose tool is filtered out of the MCP surface.
    // These tools require a UI context MCP clients can't provide.
    for (role, deviceId) in [("source", source), ("dest", dest)] {
        guard let id = deviceId else { continue }
        if let device = DeviceService.shared.get(id: id),
           mcpHiddenTools.contains(device.tool) {
            throw MCPError.invalidParams(
                "Device '\(id)' is UI-only and cannot be run via MCP "
                + "(\(role) role). Trigger this flow from the app."
            )
        }
    }

    // D.5 — Mode 1 approval gate. Runs before any timeout so user
    // think-time isn't clock-limited. Stdio (.stdio invoker) skips.
    if MCPInvokerContext.current == .inAppMCP {
        let decision = await FlowApprovalGate.shared.request(
            FlowApprovalRequest(sourceDeviceId: source, destDeviceId: dest)
        )
        if case .deny(let reason) = decision {
            MCPActivityLog.shared.append("denied — \(reason)", isError: true)
            return flowDeniedResult(reason: reason)
        }
    }

    // Dest-only mode: SecuredBox must already have data
    if source == nil, let dest {
        return try await handleDestOnly(dest, alreadyApproved: true)
    }

    // Source-only pulls use a per-call FlowEngine so multiple pulls can run concurrently.
    // Source+dest flows use FlowEngine.shared (single active dest at a time).
    let useSharedEngine = dest != nil

    return try await withThrowingTaskGroup(of: CallTool.Result.self) { group in
        group.addTask { [source] in
            try await withCheckedThrowingContinuation { continuation in
                Task { @MainActor in
                    let engine: FlowEngine
                    if useSharedEngine {
                        engine = .shared
                        // Guard before setting onEvent — prevents overwriting another caller's callback
                        guard engine.state != .running else {
                            let payload: [String: Any] = [
                                "events": [["event": "failed", "error": "A flow is already running. Wait for it to complete."]],
                                "result": "failed"
                            ]
                            continuation.resume(returning: CallTool.Result(content: [mcpText(jsonString(payload))], isError: true))
                            return
                        }
                    } else {
                        engine = FlowEngine(deviceService: .shared, registry: .shared)
                    }

                    var events: [[String: Any]] = []

                    engine.onEvent = { event in
                        mcpLogFlowEvent(event)
                        switch event {
                        case .started(let flowId):
                            events.append(["event": "started", "flowId": flowId])
                        case .stepComplete(let flowId, let deviceId, let result):
                            var dict: [String: Any] = [
                                "event": "stepComplete", "flowId": flowId, "deviceId": deviceId,
                                "success": result.success, "count": result.count, "message": result.message
                            ]
                            if !result.warnings.isEmpty { dict["warnings"] = result.warnings }
                            events.append(dict)
                        case .complete(let flowId, let preflight):
                            events.append(["event": "complete", "flowId": flowId])
                            var payload: [String: Any] = ["events": events, "result": "complete"]
                            // Source-only pull: include SecuredBox snapshot so agent sees what landed
                            if dest == nil {
                                payload["securedBox"] = securedBoxSnapshot()
                            }
                            // Dest flow: include preflight report (schema mapping / loss)
                            if let preflight {
                                payload["preflight"] = preflightSnapshot(preflight)
                            }
                            continuation.resume(returning: CallTool.Result(content: [mcpText(jsonString(payload))]))
                        case .failed(let flowId, let deviceId, let error):
                            events.append(["event": "failed", "flowId": flowId,
                                           "deviceId": deviceId as Any, "error": error])
                            let payload: [String: Any] = ["events": events, "result": "failed"]
                            continuation.resume(returning: CallTool.Result(content: [mcpText(jsonString(payload))], isError: true))
                        }
                    }

                    if let source, let dest {
                        engine.run(source, dest)
                    } else if let source {
                        engine.run(source)
                    }
                }
            }
        }

        group.addTask {
            try await Task.sleep(for: .seconds(60))
            throw MCPError.internalError("Flow timed out after 60 seconds")
        }

        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

/// Dest-only mode: push SecuredBox contents to a destination.
/// SecuredBox must already be populated (e.g. via a source pull).
/// Computes preflight, then runs the dest device as a single-device flow (no clear).
///
/// `alreadyApproved` short-circuits the Mode 1 approval when the caller
/// (`handleRun`) has already consulted the gate.
private func handleDestOnly(_ destDeviceId: String, alreadyApproved: Bool = false) async throws -> CallTool.Result {
    guard !SecuredBox.shared.isEmpty else {
        throw MCPError.invalidParams(
            "SecuredBox is empty. Run a source pull first to populate SecuredBox."
        )
    }

    if !alreadyApproved, MCPInvokerContext.current == .inAppMCP {
        let decision = await FlowApprovalGate.shared.request(
            FlowApprovalRequest(sourceDeviceId: nil, destDeviceId: destDeviceId)
        )
        if case .deny(let reason) = decision {
            MCPActivityLog.shared.append("denied — \(reason)", isError: true)
            return flowDeniedResult(reason: reason)
        }
    }

    return try await withThrowingTaskGroup(of: CallTool.Result.self) { group in
        group.addTask {
            try await withCheckedThrowingContinuation { continuation in
                Task { @MainActor in
                    let engine = FlowEngine.shared

                    // Guard before setting onEvent — prevents overwriting another caller's callback
                    guard engine.state != .running else {
                        let payload: [String: Any] = [
                            "events": [["event": "failed", "error": "A flow is already running. Wait for it to complete."]],
                            "result": "failed"
                        ]
                        continuation.resume(returning: CallTool.Result(content: [mcpText(jsonString(payload))], isError: true))
                        return
                    }

                    // Compute preflight snapshot before execution (FlowEngine handles filtering)
                    let preflightReport = engine.preflight(destDeviceId: destDeviceId)

                    var events: [[String: Any]] = []

                    engine.onEvent = { event in
                        mcpLogFlowEvent(event)
                        switch event {
                        case .started(let flowId):
                            events.append(["event": "started", "flowId": flowId])
                        case .stepComplete(let flowId, let deviceId, let result):
                            var dict: [String: Any] = [
                                "event": "stepComplete", "flowId": flowId, "deviceId": deviceId,
                                "success": result.success, "count": result.count, "message": result.message
                            ]
                            if !result.warnings.isEmpty { dict["warnings"] = result.warnings }
                            events.append(dict)
                        case .complete(let flowId, _):
                            events.append(["event": "complete", "flowId": flowId])
                            var payload: [String: Any] = [
                                "events": events,
                                "result": "complete",
                                "mode": "dest-only",
                            ]
                            if let preflight = preflightReport {
                                payload["preflight"] = preflightSnapshot(preflight)
                            }
                            continuation.resume(returning: CallTool.Result(content: [mcpText(jsonString(payload))]))
                        case .failed(let flowId, let deviceId, let error):
                            events.append(["event": "failed", "flowId": flowId,
                                           "deviceId": deviceId as Any, "error": error])
                            let payload: [String: Any] = ["events": events, "result": "failed"]
                            continuation.resume(returning: CallTool.Result(content: [mcpText(jsonString(payload))], isError: true))
                        }
                    }

                    // Single-device run: FlowEngine won't clear SecuredBox
                    engine.run(destDeviceId, action: .write)
                }
            }
        }

        group.addTask {
            try await Task.sleep(for: .seconds(60))
            throw MCPError.internalError("Flow timed out after 60 seconds")
        }

        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

private func flowDeniedResult(reason: String) -> CallTool.Result {
    let payload: [String: Any] = [
        "events": [["event": "denied", "reason": reason]],
        "result": "denied"
    ]
    return CallTool.Result(content: [mcpText(jsonString(payload))], isError: true)
}

func handleFlows() async -> CallTool.Result {
    let flows = await MainActor.run { ToolRegistry.shared.getValidFlows() }
    let items: [[String: String]] = flows.map { pair in
        ["source": pair.source.id, "sourceName": pair.source.name,
         "dest": pair.dest.id, "destName": pair.dest.name]
    }
    return CallTool.Result(content: [mcpText(jsonString(["count": items.count, "flows": items]))])
}
