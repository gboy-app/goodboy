// Runtime-mutable state passed from the host (app or binary) to MCP
// handlers so responses reflect host-level configuration without
// restarting the server.
//
// Today the only knob is `hiddenToolIds`: tool IDs to filter from the
// MCP surface beyond the static `mcpHiddenTools` set. The engine doesn't
// know why a tool is hidden — the host decides (debug modes, experimental
// flags, dynamic feature gating, etc.).

import Foundation
import os.lock

public struct MCPFeatureFlags: Sendable {
    public var hiddenToolIds: Set<String>

    public init(hiddenToolIds: Set<String> = []) {
        self.hiddenToolIds = hiddenToolIds
    }
}

public final class MCPFeatureFlagsStore: @unchecked Sendable {
    public static let shared = MCPFeatureFlagsStore()

    private let lock = OSAllocatedUnfairLock(initialState: MCPFeatureFlags())

    public var current: MCPFeatureFlags {
        lock.withLock { $0 }
    }

    public func update(_ transform: @Sendable (inout MCPFeatureFlags) -> Void) {
        lock.withLock { transform(&$0) }
    }

    private init() {}
}
