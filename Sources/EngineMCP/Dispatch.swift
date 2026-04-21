import Foundation
import MCP

/// Transport-agnostic dispatch for all Goodboy MCP tools. The executable
/// (stdio) or the in-app HTTP server (Mode 1) calls this after routing
/// `CallTool` requests through its transport. Library never touches stdout.
public func handleToolCall(_ params: CallTool.Parameters) async throws -> CallTool.Result {
    switch params.name {
    case "goodboy_tools":          return await handleTools()
    case "goodboy_devices":           return await handleDevices()
    case "goodboy_run":               return try await handleRun(params.arguments)
    case "goodboy_flows":             return await handleFlows()
    case "goodboy_chrome_profiles":   return handleChromeProfiles()
    case "goodboy_chrome_status":     return handleChromeStatus()
    case "goodboy_device_delete":     return try handleDeviceDelete(params.arguments)
    case "goodboy_device_create":     return try await handleDeviceCreate(params.arguments)
    case "goodboy_device_edit":       return try await handleDeviceEdit(params.arguments)
    case "goodboy_keychain_set":      return try await handleKeychainSet(params.arguments)
    case "goodboy_securedbox":        return handleSecuredBox()
    #if DEBUG
    case "goodboy_securedbox_dump":   return handleSecuredBoxDump(params.arguments)
    case "goodboy_securedbox_clear":  return handleSecuredBoxClear()
    case "goodboy_securedbox_delete": return try handleSecuredBoxDelete(params.arguments)
    #endif
    case "goodboy_keychain_dev":      return try await handleKeychainDev(params.arguments)
    default:
        throw MCPError.invalidParams("Unknown tool: \(params.name)")
    }
}
