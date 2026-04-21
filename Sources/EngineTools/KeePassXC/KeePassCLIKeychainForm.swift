// KeychainFormProvider for KeePassXC CLI.
// Schema: just dbPassword. Auth testing moved to KeePassCLITool.connect().

import Foundation
import FlowEngine

public final class KeePassCLIKeychainForm: KeychainFormProvider, @unchecked Sendable {

    private let keychainPrefix: String
    private let keychain: KeychainProtocol

    public init(keychainPrefix: String, dbPath: String? = nil, keyFile: String? = nil,
                keychain: KeychainProtocol = Keychain.devices) {
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
