import Foundation

// Tools registered with ToolRegistry but filtered from the MCP surface.
// Used when a tool is UI-only — its flows require a system UI context
// (e.g. an Apple Passwords CXP activity) that MCP clients can't provide.
//
// The set is tool-id-keyed and tier-agnostic. `"icloud"` is a slug, not a
// paid-feature marker; the engine doesn't know whether the caller registered
// iCloud as a free-closed app-target tool or as part of some future bundle.
//
// For host-driven dynamic hiding, set
// `MCPFeatureFlagsStore.shared.hiddenToolIds`. Handlers union both via
// `mcpEffectiveHiddenTools()`.
public let mcpHiddenTools: Set<String> = ["icloud"]

/// Static UI-only set unioned with whatever the host has set in
/// `MCPFeatureFlagsStore`. Callers that filter MCP output by tool ID
/// should use this, not `mcpHiddenTools` directly.
public func mcpEffectiveHiddenTools() -> Set<String> {
    mcpHiddenTools.union(MCPFeatureFlagsStore.shared.current.hiddenToolIds)
}
