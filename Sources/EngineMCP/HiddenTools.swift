import Foundation

// Tools registered with ToolRegistry but filtered from the MCP surface.
// Used when a tool is UI-only — its flows require a system UI context
// (e.g. an Apple Passwords CXP activity) that MCP clients can't provide.
//
// The set is tool-id-keyed and tier-agnostic. `"icloud"` is a slug, not a
// paid-feature marker; the engine doesn't know whether the caller registered
// iCloud as a free-closed app-target tool or as part of some future bundle.
//
// If a second UI-only tool ever joins this set, the right refactor is a
// `Tool.isMCPExposed` protocol flag rather than growing this list. For one
// entry, a named constant with a comment beats the flag.
public let mcpHiddenTools: Set<String> = ["icloud"]
