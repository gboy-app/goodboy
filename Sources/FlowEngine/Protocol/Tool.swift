// The plugin contract. Every Goodboy tool — shipped with the app
// or registered by third-party code — conforms to this protocol and
// only this protocol. The engine never sees a concrete tool type.
//
// This file is the public API surface of FlowEngine. Adding a
// requirement here is a major-version bump; removing one must go
// through deprecate-then-remove (see Protocol/README.md).

import Foundation

/// Every Goodboy Tool conforms to this protocol. Tools are
/// self-describing: they declare what they can do, and the registry
/// discovers them at runtime.
public protocol Tool: Sendable {
    /// Unique identifier (e.g., "chrome", "json").
    static var id: String { get }

    /// Human-readable name (e.g., "Chrome").
    static var name: String { get }

    /// What this Tool does.
    static var description: String { get }

    /// What credential types does this Tool support?
    static var supportedTypes: [BoxItemType] { get }

    /// Typed parameter schema for this Tool.
    static var paramSchema: [ParamSpec] { get }

    /// All possible device slugs this tool can create. Defines
    /// the full vocabulary of device IDs for training data.
    static var slugPool: [SlugEntry] { get }

    /// Can this Tool read (import) for the given slug? Capabilities
    /// vary per slug — e.g. Chrome can write to "default" but not "brave".
    func canRead(slug: String) -> Bool

    /// Can this Tool write (export) for the given slug?
    func canWrite(slug: String) -> Bool

    /// Cheap status check: "Is this device likely usable right now?"
    /// Checks binary exists, files exist, params present, cached service
    /// state. No network, no auth prompts, no expensive CLI calls.
    /// Returns empty array if ready, or structured DeviceError objects.
    func check(params: [String: String]) -> [DeviceError]

    /// Real auth test: "Actually verify I work." Same auth code that
    /// execute() uses — not a separate path. Called by FlowEngine
    /// before execute(); Settings views call it for live sign-in feedback.
    /// Throws on failure with actionable error.
    func connect(params: [String: String]) throws

    init()

    /// Non-invasive discovery: what can this tool see on this machine?
    /// Returns metadata (counts, paths, status) — never secrets.
    /// Default: empty dict (nothing to discover beyond check).
    func discover() -> [String: Any]

    /// Suggest device configurations based on what this tool can see.
    /// Returns an array of config dicts — one per suggested device. Each
    /// dict contains only non-keychain param values. Returns empty array
    /// if nothing usable found or no sensible default.
    func suggestDeviceConfigs() -> [[String: String]]

    /// Normalize a device config for comparison and storage. Chrome
    /// tools resolve profile names/emails to folder paths.
    /// Default: returns config unchanged.
    func normalizeConfig(_ config: [String: String]) -> [String: String]

    /// Paths to backing files whose mtime signals data changes. Used
    /// for lightweight change detection on page load (stat() only).
    /// Default: empty (no files to watch — socket-based or CXP tools).
    func watchedFiles(params: [String: String]) -> [String]

    /// Lightweight credential count for display in the device list.
    /// Returns nil if counting requires user interaction (e.g. KeePass
    /// master password). Default: nil.
    func credentialCount(params: [String: String]) -> Int?

    /// Data fields this tool produces (source) or accepts (dest).
    /// Instance method so multi-format tools (CSV, JSON) can
    /// dispatch on params["format"]. Default: [] (unknown schema).
    func dataSchema(params: [String: String]) -> [DataSchemaField]

    /// Execute the Tool.
    /// - Parameters:
    ///   - action: .read (source → box) or .write (box → dest).
    ///   - params: Tool-specific parameters.
    ///   - securedBox: The credential hub to read from / write to.
    /// - Returns: ToolResult with success/failure and metadata.
    func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult
}

// MARK: - Defaults

extension Tool {
    public static var paramSchema: [ParamSpec] { [] }
    public static var slugPool: [SlugEntry] {
        [SlugEntry(slug: "default", name: Self.name, config: [:])]
    }
    public func canRead(slug: String) -> Bool { false }
    public func canWrite(slug: String) -> Bool { false }
    public func check(params: [String: String]) -> [DeviceError] { [] }
    public func connect(params: [String: String]) throws {}
    public func discover() -> [String: Any] { [:] }
    public func suggestDeviceConfigs() -> [[String: String]] { [] }
    public func normalizeConfig(_ config: [String: String]) -> [String: String] { config }
    public func watchedFiles(params: [String: String]) -> [String] { [] }
    public func credentialCount(params: [String: String]) -> Int? { nil }
    public func dataSchema(params: [String: String]) -> [DataSchemaField] { [] }
}
