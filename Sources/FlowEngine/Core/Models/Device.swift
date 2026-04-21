// A Device is a named, saved configuration of a Tool.
// Device IDs encode tool + slug: "chrome-default", "keepasscli-secondary".
// No direction in the ID — capabilities are expressed by canRead/canWrite booleans.

import Foundation

public struct Device: Codable, Sendable, Identifiable {
    /// Unique ID: "{tool}-{slug}" e.g. "chrome-default"
    public let id: String
    /// Tool base name: "chrome", "keepasscli", "bitwarden"
    public let tool: String
    /// Slug within the tool: "default", "brave", "secondary"
    public let slug: String
    /// Display name: "Chrome", "Brave", "KeePass CLI"
    public var name: String
    /// Can this device read/import credentials?
    public var canRead: Bool
    /// Can this device write/export credentials?
    public var canWrite: Bool
    /// Non-keychain config values only. Keychain params go to macOS Keychain.
    public var config: [String: String]
    /// Grouping: "browsers", "cli", "files"
    public var category: String
    /// Secondary label: email, db filename
    public var subtitle: String?
    /// Chrome profile display name (from Chrome Preferences)
    public var profileName: String?
    /// User-pinned in UI
    public var pinned: Bool
    /// Last successful use
    public var lastUsed: Date?
    /// When this device was created
    public let createdAt: Date
    /// File-size fingerprint of backing files at last scan (for change detection).
    public var fingerprint: String?
    /// Cached credential count (updated on creation and when fingerprint changes)
    public var credentialCount: Int?
    /// Last time the stored credentials successfully authenticated against the
    /// tool (set by `DeviceService.markVerified`, cleared by Sign Out).
    ///
    /// This is the only honest "connected" signal we have — each tool's auth
    /// lifecycle lives behind a CLI that only answers when invoked, so a live
    /// "is connected right now?" bit can't exist. "Last verified 3 min ago" is
    /// what the UI can truthfully say.
    public var lastVerifiedAt: Date?

    /// User-facing message from the most recent failed auth — set by
    /// `DeviceService.markFailed`, cleared by `markVerified` or Sign Out.
    /// Persisted so the sidebar badge + device card state keep showing
    /// "Setup needed" across app restarts until a successful verify
    /// clears it. Carries the humanized string (e.g. "The master password
    /// is incorrect.") not a raw stack trace.
    public var lastAuthError: String?

    public init(id: String, tool: String, slug: String, name: String,
                canRead: Bool, canWrite: Bool,
                config: [String: String] = [:], category: String = "",
                subtitle: String? = nil, profileName: String? = nil, pinned: Bool = false,
                lastUsed: Date? = nil, createdAt: Date,
                fingerprint: String? = nil, credentialCount: Int? = nil,
                lastVerifiedAt: Date? = nil, lastAuthError: String? = nil) {
        self.id = id
        self.tool = tool
        self.slug = slug
        self.name = name
        self.canRead = canRead
        self.canWrite = canWrite
        self.config = config
        self.category = category
        self.subtitle = subtitle
        self.profileName = profileName
        self.pinned = pinned
        self.lastUsed = lastUsed
        self.createdAt = createdAt
        self.fingerprint = fingerprint
        self.credentialCount = credentialCount
        self.lastVerifiedAt = lastVerifiedAt
        self.lastAuthError = lastAuthError
    }
}
