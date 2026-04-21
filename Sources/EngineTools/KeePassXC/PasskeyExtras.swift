// Passkey extras key constants and Base64Url helpers.
// Used by KeePass XML parser/generator and Bitwarden JSON parser.

import Foundation
import FlowEngine

/// KeePassXC Browser Extension custom field keys for passkey data in KDBX entries.
public enum KPEXKey {
    public static let credentialID  = "KPEX_PASSKEY_CREDENTIAL_ID"
    public static let privateKeyPEM = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
    public static let relyingParty  = "KPEX_PASSKEY_RELYING_PARTY"
    public static let username      = "KPEX_PASSKEY_USERNAME"
    public static let userHandle    = "KPEX_PASSKEY_USER_HANDLE"
    public static let generatedUserID = "KPEX_PASSKEY_GENERATED_USER_ID"
}

/// Keys used in BoxItem.extras for passkey data.
public enum PasskeyExtrasKey {
    public static let rpId          = "passkey_rpId"
    public static let credentialId  = "passkey_credentialId"
    public static let userHandle    = "passkey_userHandle"
    public static let privateKeyPEM = "passkey_privateKeyPEM"
    public static let username      = "passkey_username"
}

/// Base64Url ↔ standard Base64 conversion.
public enum Base64Url {

    /// Convert Base64Url-encoded string to standard Base64.
    public static func toBase64(_ base64url: String) -> String {
        var s = base64url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 {
            s += String(repeating: "=", count: 4 - remainder)
        }
        return s
    }

    /// Convert standard Base64 string to Base64Url (no padding).
    public static func fromBase64(_ base64: String) -> String {
        base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
