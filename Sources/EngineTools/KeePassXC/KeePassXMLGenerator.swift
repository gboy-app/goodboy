// Generates KeePass XML from BoxItems for `keepassxc-cli import`.
// Produces a minimal valid KeePass XML envelope with entries including
// KPEX passkey custom string fields.
//
// Used when writing passkey data that can't be set via `set-login` or `add`.
//
// UUID generation: deterministic UUID based on content hash (url + username + rpId)
// for idempotent import+merge operations. Falls back to random UUID when no stable key.

import Foundation
import CryptoKit
import FlowEngine

public enum KeePassXMLGenerator {

    /// Generate a valid KeePass XML string from BoxItems.
    /// - Parameters:
    ///   - credentials: Credentials to include as entries.
    ///   - groupName: Optional group name for entries (defaults to "Root").
    /// - Returns: A KeePass XML string ready for `keepassxc-cli import`.
    public static func generate(credentials: [BoxItem], groupName: String? = nil) -> String {
        var xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        xml += "<KeePassFile>\n"
        xml += "\t<Meta>\n"
        xml += "\t\t<Generator>Goodboy</Generator>\n"
        xml += "\t</Meta>\n"
        xml += "\t<Root>\n"
        xml += "\t\t<Group>\n"
        xml += "\t\t\t<Name>\(escapeXML(groupName ?? "Root"))</Name>\n"

        for credential in credentials {
            xml += generateEntry(credential)
        }

        xml += "\t\t</Group>\n"
        xml += "\t</Root>\n"
        xml += "</KeePassFile>\n"
        return xml
    }

    // MARK: - Private

    private static func generateEntry(_ cred: BoxItem) -> String {
        var entry = "\t\t\t<Entry>\n"

        // UUID: deterministic based on content hash for idempotent merge
        let uuid = deterministicUUID(for: cred)
        entry += "\t\t\t\t<UUID>\(uuid)</UUID>\n"

        // Standard fields
        entry += stringElement(key: "Title", value: cred.extras["title"] ?? cred.url)
        entry += stringElement(key: "URL", value: cred.url)
        entry += stringElement(key: "UserName", value: cred.username)
        if let password = cred.password {
            entry += stringElement(key: "Password", value: password)
        }
        if let notes = cred.extras["notes"] {
            entry += stringElement(key: "Notes", value: notes)
        }

        // KPEX passkey attributes (BoxItem extras → KPEX custom strings)
        if let rpId = cred.extras[PasskeyExtrasKey.rpId] {
            entry += stringElement(key: KPEXKey.relyingParty, value: rpId)
        }
        if let credId = cred.extras[PasskeyExtrasKey.credentialId] {
            // BoxItem stores as standard Base64; KPEX expects Base64Url
            entry += stringElement(key: KPEXKey.credentialID, value: Base64Url.fromBase64(credId))
        }
        if let userHandle = cred.extras[PasskeyExtrasKey.userHandle] {
            entry += stringElement(key: KPEXKey.userHandle, value: Base64Url.fromBase64(userHandle))
        }
        if let privateKey = cred.extras[PasskeyExtrasKey.privateKeyPEM] {
            entry += stringElement(key: KPEXKey.privateKeyPEM, value: privateKey)
        }
        if let pkUsername = cred.extras[PasskeyExtrasKey.username] {
            entry += stringElement(key: KPEXKey.username, value: pkUsername)
        }

        // TOTP
        if let otp = cred.extras["otpAuth"] {
            entry += stringElement(key: "otp", value: otp)
        }

        entry += "\t\t\t</Entry>\n"
        return entry
    }

    private static func stringElement(key: String, value: String) -> String {
        "\t\t\t\t<String><Key>\(escapeXML(key))</Key><Value>\(escapeXML(value))</Value></String>\n"
    }

    /// Generate a deterministic UUID from entry content for idempotent import+merge.
    /// Uses SHA-256 of (url + username + rpId) truncated to 16 bytes, base64-encoded.
    static func deterministicUUID(for cred: BoxItem) -> String {
        let rpId = cred.extras[PasskeyExtrasKey.rpId] ?? ""
        let seed = "\(cred.url)|\(cred.username)|\(rpId)"
        let hash = SHA256.hash(data: Data(seed.utf8))
        // KeePass UUIDs are 16 bytes base64-encoded
        let uuidBytes = Data(Array(hash.prefix(16)))
        return uuidBytes.base64EncodedString()
    }

    /// XML-escape special characters.
    static func escapeXML(_ string: String) -> String {
        string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}
