// Protocol for the standalone auth form. Bundles schema + storage + validation.
// Each tool family provides an implementation. The UI form talks to this only.

import Foundation

public protocol KeychainFormProvider: Sendable {
    /// Save a value. Provider handles account naming internally.
    func save(key: String, value: String) throws

    /// Load a stored value. Returns nil if not set.
    ///
    /// Reads the secret payload and may trigger the macOS Keychain ACL
    /// prompt on first access. Prefer `exists(key:)` when you only need
    /// to know whether a value is set.
    func load(key: String) -> String?

    /// Attributes-only presence check. Does not read the secret payload,
    /// so macOS will not prompt the user for access. Use this on view
    /// `onAppear` and anywhere the UI only needs "is this set?" rather
    /// than the value itself.
    func exists(key: String) -> Bool

    /// Delete a stored value.
    func delete(key: String)

    // MARK: - Connect-style providers (e.g. Chrome)

    /// True if this provider uses a connect/disconnect flow instead of user-typed fields.
    /// Default: false.
    var isConnectStyle: Bool { get }

    /// Whether the provider is currently connected (key exists in keychain).
    var isConnected: Bool { get }

    /// Perform the connect action (e.g. extract browser key). Throws on failure.
    func connect() throws

    /// Disconnect — remove stored credentials.
    func disconnect()
}

// Default implementations.
public extension KeychainFormProvider {
    /// Fallback existence check that delegates to `load` — triggers a prompt.
    /// Override in concrete providers to use the keychain's attributes-only
    /// API so `onAppear` doesn't surprise the user with a password dialog.
    func exists(key: String) -> Bool { load(key: key) != nil }

    var isConnectStyle: Bool { false }
    var isConnected: Bool { false }
    func connect() throws {}
    func disconnect() {}
}
