// Protocol-based keychain with macOS Keychain (SecItem APIs) backend.
// InMemoryKeychain available for tests.
//
// Two pre-built instances cover all Goodboy needs:
//    Keychain.devices  — device-specific keychain params (API keys, tokens)
//    Keychain.app      — app-level keychain params (DB encryption key, etc.)

import Foundation

// MARK: - Protocol

public protocol KeychainProtocol: Sendable {
    func save(account: String, value: String) throws
    func load(account: String) -> String?
    /// Presence check that never reads the secret value — does not trigger the
    /// macOS Keychain ACL prompt. Use this wherever only existence is needed.
    func exists(account: String) -> Bool
    func delete(account: String)
    func deleteAll(matching prefix: String)
    func listAccounts() -> [String]
    func clear()
}

// MARK: - Keychain (entry point)

public enum Keychain {
    public static let devices: KeychainProtocol = SystemKeychain(service: "app.gboy.goodboy.devices")
    public static let app: KeychainProtocol = SystemKeychain(service: "app.gboy.goodboy")

    /// For testing: create an isolated in-memory store.
    public static func testStore() -> KeychainProtocol {
        InMemoryKeychain()
    }

    // MARK: - System Login Keychain (read-only)

    /// Read a password from the macOS login keychain (any service/account).
    /// May trigger a macOS Keychain authorization dialog on first access per item.
    public static func readSystemKeychain(service: String, account: String) throws -> String {
        let reader = SystemKeychain(service: service)
        guard let value = reader.load(account: account), !value.isEmpty else {
            throw KeychainError.systemReadFailed(
                "Cannot read '\(service)' key for '\(account)'. "
                + "Ensure the app is installed and the login keychain is unlocked. "
                + "A macOS authorization dialog may appear — click 'Always Allow'.")
        }
        return value
    }
}

// MARK: - InMemoryKeychain (for tests)

public final class InMemoryKeychain: KeychainProtocol, @unchecked Sendable {

    private var store: [String: String] = [:]
    private let lock = NSLock()

    public init() {}

    public func save(account: String, value: String) throws {
        lock.lock()
        defer { lock.unlock() }
        store[account] = value
    }

    public func load(account: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return store[account]
    }

    public func exists(account: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return store[account] != nil
    }

    public func delete(account: String) {
        lock.lock()
        defer { lock.unlock() }
        store.removeValue(forKey: account)
    }

    public func deleteAll(matching prefix: String) {
        lock.lock()
        defer { lock.unlock() }
        for key in store.keys where key.hasPrefix(prefix) {
            store.removeValue(forKey: key)
        }
    }

    public func listAccounts() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return store.keys.sorted()
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        store.removeAll()
    }
}

// MARK: - SystemKeychain

import Security

public final class SystemKeychain: KeychainProtocol, @unchecked Sendable {

    private let service: String
    private let lock = NSLock()

    public init(service: String) {
        self.service = service
    }

    /// Base query with class + service. No explicit access group —
    /// macOS implicitly scopes items to the binary's signing identity.
    /// The app and the stdio `goodboy-mcp` binary are separate-mode
    /// deployments by design (constraints 4 + 6 in STRUCTURE.md);
    /// they do not share keychain items.
    private func baseQuery(account: String? = nil) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    public func save(account: String, value: String) throws {
        let data = Data(value.utf8)

        SecItemDelete(baseQuery(account: account) as CFDictionary)

        var addQuery = baseQuery(account: account)
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    public func load(account: String) -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Attributes-only existence check. Does NOT request kSecReturnData, so
    /// macOS will not prompt the user for access to the secret payload.
    public func exists(account: String) -> Bool {
        var query = baseQuery(account: account)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess
    }

    public func delete(account: String) {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }

    public func deleteAll(matching prefix: String) {
        lock.lock()
        defer { lock.unlock() }

        var query = baseQuery()
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return }

        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix(prefix) else { continue }
            delete(account: account)
        }
    }

    public func listAccounts() -> [String] {
        var query = baseQuery()
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return [] }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        SecItemDelete(baseQuery() as CFDictionary)
    }
}

// MARK: - Error

public enum KeychainError: LocalizedError {
    case saveFailed(OSStatus)
    case systemReadFailed(String)

    public var errorDescription: String? {
        switch self {
        case .saveFailed(let status): return "Keychain save failed (OSStatus \(status))"
        case .systemReadFailed(let msg): return msg
        }
    }
}
