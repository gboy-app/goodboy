// MCP handlers for keychain-backed device params: `goodboy_keychain_{set,clear}`.

import Foundation
import MCP
import FlowEngine

func handleKeychainSet(_ arguments: [String: Value]?) async throws -> CallTool.Result {
    guard let deviceId = arguments?["deviceId"]?.stringValue else {
        throw MCPError.invalidParams("Missing required parameter 'deviceId'")
    }
    guard let paramKey = arguments?["paramKey"]?.stringValue else {
        throw MCPError.invalidParams("Missing required parameter 'paramKey'")
    }

    // Validate device exists
    DeviceService.shared.reload()
    guard let device = DeviceService.shared.get(id: deviceId) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Device '\(deviceId)' not found."]))],
            isError: true
        )
    }

    // Validate paramKey is a .keychain type in the tool's paramSchema
    let manifests = await MainActor.run { ToolRegistry.shared.manifests }
    guard let manifest = manifests.first(where: { $0.id == device.tool }) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "No tool found for '\(device.tool)'."]))],
            isError: true
        )
    }

    guard let paramSpec = manifest.paramSchema.first(where: { $0.key == paramKey }) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Param '\(paramKey)' not found in \(manifest.id) paramSchema."]))],
            isError: true
        )
    }

    guard paramSpec.type == .keychain else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Param '\(paramKey)' is type '\(paramSpec.type.rawValue)', not 'keychain'. Use device config for non-keychain params."]))],
            isError: true
        )
    }

    // Accept value directly as a param — no system dialogs, no blocking.
    // The agent is responsible for collecting the value from the user.
    guard let value = arguments?["value"]?.stringValue, !value.isEmpty else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Missing required parameter 'value'. Pass the keychain value directly."]))],
            isError: true
        )
    }

    if let validation = KeychainValueValidator.validate(paramKey: paramKey, value: value) {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": validation]))],
            isError: true
        )
    }

    // Store in Keychain via Goodboy's own infrastructure
    do {
        try DeviceService.shared.setKeychain(deviceId: deviceId, paramKey: paramKey, value: value)
    } catch {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Keychain save failed: \(error.localizedDescription)"]))],
            isError: true
        )
    }

    return CallTool.Result(
        content: [mcpText(jsonString([
            "success": true,
            "message": "Param '\(paramKey)' stored in Keychain for device '\(deviceId)'.",
            "deviceId": deviceId,
            "paramKey": paramKey,
        ] as [String: Any]))]
    )
}

func handleKeychainDev(_ arguments: [String: Value]?) async throws -> CallTool.Result {
    guard let action = arguments?["action"]?.stringValue else {
        throw MCPError.invalidParams("Missing required param: action")
    }

    switch action {
    case "status":
        let status = DeviceService.shared.keychainStatus()
        let json: [String: Any] = [
            "services": status.services.map { svc -> [String: Any] in
                ["service": svc.service, "accounts": svc.accounts, "count": svc.accounts.count]
            }
        ]
        return CallTool.Result(content: [mcpText(jsonString(json))])

    case "seed":
        let targetDeviceId = arguments?["deviceId"]?.stringValue
        let bridge = ChromeBridgeRegistry.current
        let result = await MainActor.run {
            DeviceService.shared.seedKeychain(
                targetDeviceId: targetDeviceId,
                extractBrowserKey: bridge.map { b in
                    { chromeDir in try b.extractBrowserKey(chromeDir: chromeDir) }
                }
            )
        }
        let json: [String: Any] = [
            "success": result.success,
            "autoSeeded": result.autoSeeded.map { [
                "deviceId": $0.deviceId, "paramKey": $0.paramKey,
                "message": $0.message, "alreadyCached": $0.alreadyCached,
            ] as [String: Any] },
            "needsInput": result.needsInput.map { [
                "deviceId": $0.deviceId, "paramKey": $0.paramKey,
                "label": $0.label, "description": $0.description,
                "required": $0.required,
            ] as [String: Any] },
            "errors": result.errors.map { [
                "deviceId": $0.deviceId, "paramKey": $0.paramKey,
                "message": $0.message,
            ] as [String: Any] },
        ]
        return CallTool.Result(content: [mcpText(jsonString(json))])

    case "wipe":
        #if DEBUG
        let target = arguments?["target"]?.stringValue
        let result = DeviceService.shared.wipeKeychain(target: target)
        return CallTool.Result(content: [mcpText(jsonString([
            "wiped": result.wiped, "message": result.message,
        ] as [String: Any]))])
        #else
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "'wipe' is a dev-only action and is not available in release builds. To reset, open the Goodboy app and use Settings → Reset Keychain."]))],
            isError: true
        )
        #endif

    default:
        throw MCPError.invalidParams("Unknown action: \(action). Use 'status', 'seed', or 'wipe'.")
    }
}
