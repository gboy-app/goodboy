// Supporting types referenced by the Tool protocol — params,
// results, errors, events, manifest. The protocol itself lives in
// Tool.swift; data-schema types in DataSchema.swift.

import Foundation

// MARK: - Tool Error (for connect() throws)

/// Actionable error thrown by connect(). localizedDescription is user-facing.
public struct ToolError: LocalizedError, Sendable {
    public let message: String
    public var errorDescription: String? { message }
    public init(_ message: String) { self.message = message }
}

// MARK: - Device Error

public struct DeviceError: Sendable, Codable, Equatable {
    public enum Category: String, Sendable, Codable {
        case notInstalled   // software missing
        case notRunning     // app closed / DB locked / integration disabled
        case missingParam   // config or keychain value needed
        case authFailed     // credentials rejected / session expired
        case resourceGone   // file deleted, profile removed, permissions broken
    }

    public let category: Category
    public let message: String        // user-facing, actionable
    public let action: String?        // CTA label: "Open KeePassXC", "Install Chrome"
    public let actionURL: String?     // deep link, URL, or nil

    public init(category: Category, message: String, action: String? = nil, actionURL: String? = nil) {
        self.category = category
        self.message = message
        self.action = action
        self.actionURL = actionURL
    }
}

// MARK: - Param Persistence

public enum ParamPersistence: String, Sendable, Codable {
    case stored     // saved to config or keychain
    case transient  // per-run only, never persisted (e.g. ProtonPass totp)
}

// MARK: - Param Schema Types

public enum ParamType: String, Codable, Sendable {
    case string     // Free text (UI: text field)
    case path       // File/directory path (UI: file picker)
    case keychain   // Stored in Keychain, hidden in UI (UI: secure field)
    case choice     // One of N values (UI: dropdown)
    case stringList // JSON array of strings (UI: add/remove chips). Stored as JSON string in config.
}

/// Format validation for a ParamSpec. Small fixed set — not a generic
/// rule engine. Applied on-change and on-submit by the form renderer;
/// `check()` / `connect()` are still the server-side gate.
public enum ParamValidation: Sendable, Equatable {
    case email
    case url
    case minLength(Int)
    case regex(String)

    /// Returns nil if `value` passes, otherwise a short user-facing error.
    /// An empty value is considered valid here — required-ness is a
    /// separate gate, handled by the form.
    public func validate(_ value: String) -> String? {
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !v.isEmpty else { return nil }
        switch self {
        case .email:
            let pattern = #"^[^\s@]+@[^\s@]+\.[^\s@]+$"#
            return v.range(of: pattern, options: .regularExpression) != nil
                ? nil
                : "Enter a valid email address."
        case .url:
            guard let url = URL(string: v),
                  let scheme = url.scheme?.lowercased(),
                  scheme == "http" || scheme == "https",
                  let host = url.host, !host.isEmpty else {
                return "Enter a valid URL (http:// or https://)."
            }
            return nil
        case .minLength(let n):
            return v.count >= n ? nil : "Must be at least \(n) characters."
        case .regex(let pattern):
            return v.range(of: pattern, options: .regularExpression) != nil
                ? nil
                : "Doesn\u{2019}t match the expected format."
        }
    }
}

extension ParamValidation: Codable {
    private enum CodingKeys: String, CodingKey { case kind, value }
    private enum Kind: String, Codable { case email, url, minLength, regex }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .email: try c.encode(Kind.email, forKey: .kind)
        case .url:   try c.encode(Kind.url, forKey: .kind)
        case .minLength(let n):
            try c.encode(Kind.minLength, forKey: .kind)
            try c.encode(n, forKey: .value)
        case .regex(let pattern):
            try c.encode(Kind.regex, forKey: .kind)
            try c.encode(pattern, forKey: .value)
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .email: self = .email
        case .url:   self = .url
        case .minLength:
            self = .minLength(try c.decode(Int.self, forKey: .value))
        case .regex:
            self = .regex(try c.decode(String.self, forKey: .value))
        }
    }
}

public struct ParamSpec: Codable, Sendable {
    public let key: String
    public let label: String
    public let type: ParamType
    public let required: Bool
    public let description: String
    public let defaultValue: String?
    public let choices: [String]?
    /// Display labels for choices (parallel array). Falls back to `choices` values if nil.
    public let choiceLabels: [String]?
    /// False for structural params (e.g. Chrome profile) — changing them means a different device.
    public let editable: Bool
    public let persistence: ParamPersistence
    /// Optional format rule applied by the form UI. `check()` / `connect()`
    /// stay the final gate; this is purely so users see "invalid email" before
    /// they click Sign In.
    public let validation: ParamValidation?

    public init(key: String, label: String, type: ParamType, required: Bool,
                description: String, defaultValue: String? = nil, choices: [String]? = nil,
                choiceLabels: [String]? = nil,
                editable: Bool = true, persistence: ParamPersistence = .stored,
                validation: ParamValidation? = nil) {
        self.key = key
        self.label = label
        self.type = type
        self.required = required
        self.description = description
        self.defaultValue = defaultValue
        self.choices = choices
        self.choiceLabels = choiceLabels
        self.editable = editable
        self.persistence = persistence
        self.validation = validation
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.key = try c.decode(String.self, forKey: .key)
        self.label = try c.decode(String.self, forKey: .label)
        self.type = try c.decode(ParamType.self, forKey: .type)
        self.required = try c.decode(Bool.self, forKey: .required)
        self.description = try c.decode(String.self, forKey: .description)
        self.defaultValue = try c.decodeIfPresent(String.self, forKey: .defaultValue)
        self.choices = try c.decodeIfPresent([String].self, forKey: .choices)
        self.choiceLabels = try c.decodeIfPresent([String].self, forKey: .choiceLabels)
        self.editable = try c.decodeIfPresent(Bool.self, forKey: .editable) ?? true
        self.persistence = try c.decodeIfPresent(ParamPersistence.self, forKey: .persistence) ?? .stored
        self.validation = try c.decodeIfPresent(ParamValidation.self, forKey: .validation)
    }

    private enum CodingKeys: String, CodingKey {
        case key, label, type, required, description, defaultValue, choices, choiceLabels, editable, persistence, validation
    }
}

// MARK: - Supporting Types

public enum BoxItemType: String, Codable, Sendable {
    case password = "pwd"
    case otp = "otp"
    case passkey = "passkey"
}

public enum ToolAction: String, Sendable {
    case read   // Source: pull data INTO securedBox
    case write  // Destination: push data OUT OF securedBox
}

public struct ToolResult: Sendable {
    public let success: Bool
    public let count: Int           // Number of credentials processed
    public let message: String      // Human-readable result
    public let outputPath: String?  // If write action produced a file
    public let error: String?       // Error message if failed
    public let artifacts: [String]  // Output artifacts (files, URLs, etc.)
    public let warnings: [String]   // Non-fatal warnings

    public init(success: Bool, count: Int, message: String, outputPath: String? = nil, error: String? = nil, artifacts: [String] = [], warnings: [String] = []) {
        self.success = success
        self.count = count
        self.message = message
        self.outputPath = outputPath
        self.error = error
        self.artifacts = artifacts
        self.warnings = warnings
    }

    public static func success(count: Int, message: String, outputPath: String? = nil, artifacts: [String] = [], warnings: [String] = []) -> ToolResult {
        ToolResult(success: true, count: count, message: message, outputPath: outputPath, artifacts: artifacts, warnings: warnings)
    }

    public static func failure(_ error: String) -> ToolResult {
        ToolResult(success: false, count: 0, message: error, error: error)
    }

    /// Summary string for display.
    public var summary: String {
        if success {
            return message
        } else {
            return error ?? "Failed"
        }
    }
}

// MARK: - Tool Manifest (for JSON serialization)

/// Serializable Tool description for registry.
public struct ToolManifest: Codable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let canBeSource: Bool
    public let canBeDestination: Bool
    public let supportedTypes: [BoxItemType]
    /// Typed parameter schema. For bundled tools, sourced from the
    /// Tool type's `paramSchema`. For external tools, populated
    /// from `manifest.json`.
    public let paramSchema: [ParamSpec]
    public let slugPool: [SlugEntry]
    public let bundled: Bool        // true = ships with app, false = external
    public let path: String?        // External Tools: path to binary/plugin

    public init(from tool: any Tool.Type, bundled: Bool = true, path: String? = nil) {
        let instance = tool.init()
        self.id = tool.id
        self.name = tool.name
        self.description = tool.description
        self.canBeSource = tool.slugPool.contains { instance.canRead(slug: $0.slug) }
        self.canBeDestination = tool.slugPool.contains { instance.canWrite(slug: $0.slug) }
        self.supportedTypes = tool.supportedTypes
        self.paramSchema = tool.paramSchema
        self.slugPool = tool.slugPool
        self.bundled = bundled
        self.path = path
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case description
        case canBeSource
        case canBeDestination
        case supportedTypes
        case paramSchema
        case slugPool
        case bundled
        case path
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(String.self, forKey: .id)
        self.name = try c.decode(String.self, forKey: .name)
        self.description = try c.decode(String.self, forKey: .description)
        self.canBeSource = try c.decode(Bool.self, forKey: .canBeSource)
        self.canBeDestination = try c.decode(Bool.self, forKey: .canBeDestination)
        self.supportedTypes = try c.decode([BoxItemType].self, forKey: .supportedTypes)
        self.paramSchema = try c.decodeIfPresent([ParamSpec].self, forKey: .paramSchema) ?? []
        self.slugPool = try c.decodeIfPresent([SlugEntry].self, forKey: .slugPool) ?? []
        self.bundled = try c.decode(Bool.self, forKey: .bundled)
        self.path = try c.decodeIfPresent(String.self, forKey: .path)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(description, forKey: .description)
        try c.encode(canBeSource, forKey: .canBeSource)
        try c.encode(canBeDestination, forKey: .canBeDestination)
        try c.encode(supportedTypes, forKey: .supportedTypes)
        if !paramSchema.isEmpty {
            try c.encode(paramSchema, forKey: .paramSchema)
        }
        if !slugPool.isEmpty {
            try c.encode(slugPool, forKey: .slugPool)
        }
        try c.encode(bundled, forKey: .bundled)
        try c.encodeIfPresent(path, forKey: .path)
    }
}

// MARK: - Tool Progress (for async execution)

/// A progress update from a long-running Tool execution.
public struct ToolProgress: Sendable {
    public let stage: String        // Stage name (e.g., "Connecting", "Reading")
    public let message: String      // Progress message
    public let percent: Double?     // Optional completion percentage (0.0-1.0)

    public init(stage: String, message: String, percent: Double? = nil) {
        self.stage = stage
        self.message = message
        self.percent = percent
    }
}

// MARK: - Slug Entry (for device vocabulary)

/// Declares one possible device slug for a Tool. The slugPool is
/// the full vocabulary — every device ID this tool can ever create.
public struct SlugEntry: Codable, Sendable {
    public let slug: String              // "brave", "bitwarden", "default"
    public let name: String              // "Brave Reader", "Bitwarden JSON Export"
    public let config: [String: String]  // ["chromeDir": "BraveSoftware/Brave-Browser"]

    public init(slug: String, name: String, config: [String: String] = [:]) {
        self.slug = slug
        self.name = name
        self.config = config
    }
}

// MARK: - Tool Event (for async communication)

/// Events emitted during Tool execution.
public enum ToolEvent: Sendable {
    case progress(ToolProgress)
    case completed(ToolResult)
}
