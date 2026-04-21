// Host-provided MCP tools. Mirrors the registration pattern used by
// `MCPActivityLog.shared.register(sink:)` and `FlowApprovalGate` —
// the host (app target, or any caller embedding `InAppMCPServer`) can
// register additional MCP tool definitions + a dispatcher handler
// before the server starts. When a request arrives, `InAppMCPServer`
// checks built-in engine tools first and falls through to the host
// handler for anything unrecognized.
//
// The hook is opaque to the engine. The engine doesn't know or care
// what the host is exposing — host-specific tools, dev helpers, an
// experimental endpoint, or nothing at all (no-op when unregistered).
// `goodboy-mcp` never registers anything and therefore ships only the
// engine's built-in tool set.

import Foundation
import os.lock
// Re-export MCP so any module importing EngineMCP can construct
// `MCP.Tool` values to pass into `MCPHostTools.shared.register(...)`
// without taking a direct dependency on the swift-sdk package.
@_exported import MCP

public final class MCPHostTools: @unchecked Sendable {

    public static let shared = MCPHostTools()

    public typealias Handler = @Sendable (CallTool.Parameters) async throws -> CallTool.Result?

    private struct State {
        var tools: [MCP.Tool] = []
        var handler: Handler?
    }

    private let lock = OSAllocatedUnfairLock(initialState: State())

    public var tools: [MCP.Tool] {
        lock.withLock { $0.tools }
    }

    /// Register host tools and their dispatcher. Call once at startup,
    /// before `InAppMCPServer.start()`. Subsequent calls overwrite.
    public func register(tools: [MCP.Tool], handler: @escaping Handler) {
        lock.withLock { state in
            state.tools = tools
            state.handler = handler
        }
    }

    /// Invoke the registered handler. Returns `nil` if no host is
    /// registered or the host doesn't recognize the tool; callers
    /// treat `nil` as "unknown tool" and surface a standard error.
    public func handle(_ params: CallTool.Parameters) async throws -> CallTool.Result? {
        let handler = lock.withLock { $0.handler }
        return try await handler?(params)
    }

    private init() {}
}
