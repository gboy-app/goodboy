// Per-param-key validation for goodboy_keychain_set. Rejects
// malformed values before anything reaches SecItemAdd or a CLI
// subprocess — closes M5.
//
// Returned message names the rule that failed; it never echoes the
// rejected value (privacy leak + pointless against a caller that
// already knows what they sent).

import Foundation

enum KeychainValueValidator {

    private static let maxLength = 4 * 1024

    /// Return `nil` when the value is acceptable; otherwise a
    /// user-facing message for the MCP tool result.
    static func validate(paramKey: String, value: String) -> String? {
        if value.count > maxLength {
            return "Value too long: keychain params are capped at \(maxLength) bytes."
        }
        if value.contains("\0") {
            return "Value contains a null byte; keychain params must be printable text."
        }

        switch paramKey {
        case "serverUrl":
            guard let url = URL(string: value),
                  let scheme = url.scheme?.lowercased(),
                  scheme == "https",
                  let host = url.host,
                  !host.isEmpty
            else {
                return "'serverUrl' must be an absolute https:// URL with a host."
            }
            return nil

        case "safeStorageKey":
            guard let data = Data(base64Encoded: value), data.count == 16 else {
                return "'safeStorageKey' must base64-decode to exactly 16 bytes."
            }
            return nil

        case "clientId":
            // RFC 4122 UUID (any version, lowercase or uppercase).
            let pattern = #"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"#
            if value.range(of: pattern, options: .regularExpression) == nil {
                return "'clientId' must be a RFC 4122 UUID."
            }
            return nil

        case "serviceAccountToken":
            guard value.hasPrefix("ops_") else {
                return "'serviceAccountToken' must start with 'ops_'."
            }
            guard value.count >= 32 && value.count <= 256 else {
                return "'serviceAccountToken' length must be between 32 and 256 characters."
            }
            return nil

        default:
            // Unknown paramKey: only the generic length/null-byte
            // checks above apply. Individual tools can tighten
            // later via their own paramSchema.
            return nil
        }
    }
}
