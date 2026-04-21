// KeychainFormProvider for Bitwarden CLI.
// Schema: masterPassword (required), clientId + clientSecret (optional, for API key auth).
// Auth testing moved to BitwardenCLITool.connect().

import Foundation
import FlowEngine

public final class BitwardenKeychainForm: KeychainFormProvider, @unchecked Sendable {

    private let keychainPrefix: String
    private let keychain: KeychainProtocol

    public init(keychainPrefix: String, keychain: KeychainProtocol = Keychain.devices) {
        self.keychainPrefix = keychainPrefix
        self.keychain = keychain
    }

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
}
