// App-visible log of MCP activity. The SwiftUI app registers a sink
// at startup; dispatch + handlers push one line per tool call, plus
// approval decisions and per-event flow updates. Stdio invocations
// (.stdio context) bypass — no UI consumer in that transport.
//
// The sink is an at-most-once-registered closure. No-op if unset,
// so unit tests and the stdio binary don't need to wire anything.

import Foundation
import os
import FlowEngine

public struct MCPActivityEntry: Sendable {
    public let timestamp: Date
    public let line: String
    public let isError: Bool

    public init(timestamp: Date = Date(), line: String, isError: Bool = false) {
        self.timestamp = timestamp
        self.line = line
        self.isError = isError
    }
}

public final class MCPActivityLog: @unchecked Sendable {

    public static let shared = MCPActivityLog()

    public typealias Sink = @Sendable (MCPActivityEntry) -> Void

    private let lock = OSAllocatedUnfairLock<Sink?>(initialState: nil)

    private init() {}

    public func register(_ sink: @escaping Sink) {
        lock.withLock { $0 = sink }
    }

    public func append(_ line: String, isError: Bool = false) {
        let entry = MCPActivityEntry(line: line, isError: isError)
        let sink = lock.withLock { $0 }
        sink?(entry)
    }
}

/// Format a FlowEvent into a single log line and push it through
/// `MCPActivityLog.shared`. Called from inside the `FlowHandlers`
/// event observers — no-op if no sink is registered.
func mcpLogFlowEvent(_ event: FlowEvent) {
    switch event {
    case .started:
        MCPActivityLog.shared.append("flow started")
    case .stepComplete(_, let deviceId, let result):
        MCPActivityLog.shared.append("\(deviceId) — \(result.message)", isError: !result.success)
    case .complete:
        MCPActivityLog.shared.append("flow complete")
    case .failed(_, let deviceId, let error):
        let label = deviceId ?? "flow"
        MCPActivityLog.shared.append("\(label) — \(error)", isError: true)
    }
}

