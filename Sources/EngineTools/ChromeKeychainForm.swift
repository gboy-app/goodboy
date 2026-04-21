// KeychainFormProvider for Chrome/Chromium browsers.
// Connect-style: no user-typed fields. Connect extracts the browser's
// Safe Storage key via ChromeHelper, disconnect removes it.

import Foundation
import FlowEngine

public final class ChromeKeychainForm: KeychainFormProvider, @unchecked Sendable {

    private let keychainPrefix: String
    private let keychain: KeychainProtocol
    private let chromeDir: String

    public init(keychainPrefix: String, chromeDir: String? = nil,
                keychain: KeychainProtocol = Keychain.devices) {
        self.keychainPrefix = keychainPrefix
        self.keychain = keychain
        self.chromeDir = chromeDir ?? ChromeHelper.defaultChromeDir
    }

    // MARK: - KeychainFormProvider

    public func save(key: String, value: String) throws {
        try keychain.save(account: "\(keychainPrefix)\(key)", value: value)
    }

    public func load(key: String) -> String? {
        keychain.load(account: "\(keychainPrefix)\(key)")
    }

    public func exists(key: String) -> Bool {
        keychain.exists(account: "\(keychainPrefix)\(key)")
    }

    public func delete(key: String) {
        keychain.delete(account: "\(keychainPrefix)\(key)")
    }

    // MARK: - Connect-style

    public var isConnectStyle: Bool { true }

    /// Attributes-only check — doesn't surface the macOS Keychain prompt
    /// when the settings panel opens. The prompt only fires when Chrome
    /// actually reads the key to decrypt.
    public var isConnected: Bool {
        exists(key: "safeStorageKey")
    }

    public func connect() throws {
        let keyB64 = try ChromeHelper.extractBrowserKey(chromeDir: chromeDir)
        try save(key: "safeStorageKey", value: keyB64)
    }

    public func disconnect() {
        delete(key: "safeStorageKey")
    }
}
