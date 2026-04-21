// D.5 — per-flow approval gate for Mode 1 (in-app HTTP MCP).
//
// The library is transport-agnostic; UI lives in the SwiftUI app.
// Coupling goes through two seams:
//
// 1. `MCPInvokerContext.$current` — task-local set by InAppMCPServer
//     before dispatching into the handlers. Stdio (Mode 2) leaves it
//     at the default `.stdio`, so `handleRun` never asks for approval
//     there.
// 2. `FlowApprovalGate.shared` — holds an optional async provider.
//     The SwiftUI app registers a provider at startup that presents
//     an NSAlert sheet on the main window and resumes the continuation
//     on Approve/Deny. If no provider is registered, the gate fails
//     closed — never auto-approve when Mode 1 is the invoker.
//
// No timeout on the approval wait (plan §D.5). The MCP client
// experiences it as tool-call latency.

import Foundation
import os

public enum MCPInvoker: Sendable {
    case stdio
    case inAppMCP
}

public enum MCPInvokerContext {
    @TaskLocal public static var current: MCPInvoker = .stdio
}

public struct FlowApprovalRequest: Sendable {
    public let sourceDeviceId: String?
    public let destDeviceId: String?

    public init(sourceDeviceId: String?, destDeviceId: String?) {
        self.sourceDeviceId = sourceDeviceId
        self.destDeviceId = destDeviceId
    }
}

public enum FlowApprovalDecision: Sendable {
    case approve
    case deny(reason: String)
}

public final class FlowApprovalGate: @unchecked Sendable {

    public static let shared = FlowApprovalGate()

    public typealias Provider = @Sendable (FlowApprovalRequest) async -> FlowApprovalDecision

    private let lock = OSAllocatedUnfairLock<Provider?>(initialState: nil)

    private init() {}

    /// Called once, from the SwiftUI app at startup. Overwrites any
    /// previously registered provider.
    public func register(_ provider: @escaping Provider) {
        lock.withLock { $0 = provider }
    }

    /// Called from `handleRun` when the invoker is `.inAppMCP`.
    /// Fails closed if no provider is registered.
    public func request(_ req: FlowApprovalRequest) async -> FlowApprovalDecision {
        let provider = lock.withLock { $0 }
        guard let provider else {
            return .deny(reason: "Approval UI unavailable — Goodboy app is not wired for Mode 1 approval.")
        }
        return await provider(req)
    }
}
