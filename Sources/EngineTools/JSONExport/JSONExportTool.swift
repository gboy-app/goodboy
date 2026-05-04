// Dest PT: Exports credentials from SecuredBox to Bitwarden JSON format.
//
// Bitwarden JSON is the universal interchange format — every password manager
// on earth can import it. This is the only file-based export Goodboy needs.
//
// Supports passwords, OTP, passkeys, folders, favorites, and notes.
// Round-trips cleanly with BitwardenJSONParser (the source-side reader).

import Foundation
import os.log
import FlowEngine

public final class JSONExportTool: Tool {

    // MARK: - Tool Spec (static)

    public static let id = "json"
    public static let name = "Bitwarden JSON Export"
    public static let description = "Exports credentials to Bitwarden JSON — the universal interchange format importable by every password manager"
    public static let supportedTypes: [BoxItemType] = [.password, .passkey, .otp]

    public static var paramSchema: [ParamSpec] {
        [
            ParamSpec(key: "path", label: "Output File", type: .path, required: true,
                      description: "Path to output Bitwarden JSON file",
                      defaultValue: "~/Downloads/goodboy-export.json"),
            ParamSpec(key: "redact", label: "Redact Secrets", type: .choice, required: false,
                      description: "Replace passwords / TOTP / passkey keys with sentinels of form `[redacted: N chars, KIND]`. Output is no longer importable but is safe to share.",
                      defaultValue: "false",
                      choices: ["false", "true"],
                      choiceLabels: ["Off", "On"]),
        ]
    }

    public static var slugPool: [SlugEntry] {
        [
            SlugEntry(slug: "default", name: "Bitwarden JSON Export", config: [:]),
            SlugEntry(slug: "redacted", name: "Bitwarden JSON Export (Redacted)",
                      config: ["redact": "true"]),
        ]
    }

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "JSONExportTool")

    public init() {}

    // MARK: - Direction

    public func canRead(slug: String) -> Bool { false }
    public func canWrite(slug: String) -> Bool { true }

    public func dataSchema(params: [String: String]) -> [DataSchemaField] {
        [
            DataSchemaField(key: "url", type: "url", required: true),
            DataSchemaField(key: "username", type: "string", required: true),
            DataSchemaField(key: "password", type: "secret", required: false),
            DataSchemaField(key: "otpAuth", type: "secret", required: false),
            DataSchemaField(key: "notes", type: "string", required: false),
            DataSchemaField(key: "title", type: "string", required: false),
            DataSchemaField(key: "group", type: "string", required: false),
            DataSchemaField(key: "favorite", type: "string", required: false),
            DataSchemaField(key: "passkey_rpId", type: "string", required: false),
            DataSchemaField(key: "passkey_credentialId", type: "string", required: false),
            DataSchemaField(key: "passkey_userHandle", type: "string", required: false),
            DataSchemaField(key: "passkey_userName", type: "string", required: false),
            DataSchemaField(key: "passkey_userDisplayName", type: "string", required: false),
            DataSchemaField(key: "passkey_key", type: "secret", required: false),
        ]
    }

    public func watchedFiles(params: [String: String]) -> [String] {
        guard let path = params["path"], !path.isEmpty else { return [] }
        let expanded = NSString(string: path).expandingTildeInPath
        return FileManager.default.fileExists(atPath: expanded) ? [expanded] : []
    }

    public func suggestDeviceConfigs() -> [[String: String]] {
        [
            ["path": "~/Downloads/goodboy-export.json",
             "redact": "false",
             "_slug": "default", "_canRead": "false", "_canWrite": "true"],
            ["path": "~/Downloads/goodboy-export.redacted.json",
             "redact": "true",
             "_slug": "redacted", "_canRead": "false", "_canWrite": "true"],
        ]
    }

    // MARK: - Check + Connect

    public func check(params: [String: String]) -> [DeviceError] {
        guard let path = params["path"], !path.isEmpty else {
            return [DeviceError(category: .missingParam, message: "Missing 'path' param. Provide the path for the output JSON file.", action: "Select file")]
        }

        if let error = JSONExportPathPolicy.validate(path) {
            return [error]
        }

        let resolved = JSONExportPathPolicy.resolve(path)
        let dir = (resolved as NSString).deletingLastPathComponent
        guard FileManager.default.fileExists(atPath: dir) else {
            return [DeviceError(category: .resourceGone, message: "Output directory '\(dir)' does not exist. Create it first or choose a different path.", action: "Select path")]
        }
        guard FileManager.default.isWritableFile(atPath: dir) else {
            return [DeviceError(category: .resourceGone, message: "Output directory '\(dir)' is not writable. Check permissions or choose a different path.", action: "Fix permissions")]
        }
        return []
    }

    // MARK: - Execute

    public func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        guard action == .write else {
            return .failure("JSONExportTool is a destination — use action: .write to export.")
        }

        guard !securedBox.isEmpty else {
            return .failure("No credentials in securedBox. Import from a source first, then export.")
        }

        guard let path = params["path"] else { return .failure("Missing 'path'.") }
        if let policyError = JSONExportPathPolicy.validate(path) {
            return .failure(policyError.message)
        }
        let expandedPath = JSONExportPathPolicy.resolve(path)
        let redact = (params["redact"] ?? "false") == "true"

        let credentials = securedBox.items

        // Build folder lookup: unique group names → UUID
        var folderMap: [String: String] = [:]
        for cred in credentials {
            if let group = cred.extras["group"], !group.isEmpty, folderMap[group] == nil {
                folderMap[group] = UUID().uuidString.lowercased()
            }
        }

        // Build folders array
        let folders = folderMap.map { name, id in
            ExportBWFolder(id: id, name: name)
        }.sorted { $0.name < $1.name }

        // Map BoxItems → Bitwarden items
        let items = credentials.enumerated().map { _, cred -> ExportBWItem in
            let title = cred.extras["title"]
                ?? URL(string: cred.url)?.host
                ?? (cred.url.isEmpty ? "Untitled" : cred.url)

            let folderId: String? = {
                guard let group = cred.extras["group"], !group.isEmpty else { return nil }
                return folderMap[group]
            }()

            let favorite: Bool = {
                guard let fav = cred.extras["favorite"] else { return false }
                return fav == "1" || fav.lowercased() == "true"
            }()

            // Build fido2Credentials from passkey extras (if present)
            let fido2: [ExportBWFido2Credential]? = buildFido2(from: cred, redact: redact)

            let login = ExportBWLogin(
                username: cred.username.isEmpty ? nil : cred.username,
                password: redact ? Self.scrub(cred.password) : cred.password,
                totp: redact ? Self.scrub(cred.extras["otpAuth"]) : cred.extras["otpAuth"],
                uris: cred.url.isEmpty ? [] : [ExportBWURI(uri: cred.url)],
                fido2Credentials: fido2
            )

            return ExportBWItem(
                id: UUID().uuidString.lowercased(),
                folderId: folderId,
                type: 1,
                name: title,
                notes: cred.extras["notes"],
                favorite: favorite,
                login: login
            )
        }

        // Encode and write
        let envelope = ExportBWEnvelope(encrypted: false, folders: folders, items: items)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(envelope)
        try data.write(to: URL(fileURLWithPath: expandedPath))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: expandedPath
        )

        Self.log.info("Exported \(items.count) credentials to \(expandedPath, privacy: .private)")
        return .success(count: items.count, message: "Exported \(items.count) credentials to Bitwarden JSON", outputPath: expandedPath)
    }

    // MARK: - Passkey Mapping

    private func buildFido2(from cred: BoxItem, redact: Bool) -> [ExportBWFido2Credential]? {
        // Check both naming conventions: PasskeyExtrasKey (KeePass path) and dataSchema keys (iCloud path)
        guard let rpId = cred.extras[PasskeyExtrasKey.rpId] ?? cred.extras["passkey_rpId"],
              !rpId.isEmpty else { return nil }

        let credentialId = cred.extras[PasskeyExtrasKey.credentialId] ?? cred.extras["passkey_credentialId"] ?? ""

        // Key resolution: PEM-wrapped (KeePass path) → strip headers. Raw base64 (iCloud path) → use directly.
        let keyValue: String = {
            if let pem = cred.extras[PasskeyExtrasKey.privateKeyPEM], !pem.isEmpty {
                return Self.pemToBase64(pem)
            }
            return cred.extras["passkey_key"] ?? ""
        }()

        let userName = cred.extras[PasskeyExtrasKey.username]
            ?? cred.extras["passkey_userName"]
            ?? (cred.username.isEmpty ? nil : cred.username)

        let userHandle = cred.extras[PasskeyExtrasKey.userHandle]
            ?? cred.extras["passkey_userHandle"]

        let userDisplayName = cred.extras["passkey_userDisplayName"]

        let iso8601 = ISO8601DateFormatter()
        iso8601.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        return [ExportBWFido2Credential(
            credentialId: credentialId,
            keyType: "public-key",
            keyAlgorithm: "ECDSA",
            keyCurve: "P-256",
            keyValue: redact ? (Self.scrub(keyValue) ?? "") : keyValue,
            rpId: rpId,
            rpName: rpId,
            userHandle: userHandle,
            userName: userName,
            userDisplayName: userDisplayName,
            counter: "0",
            discoverable: "true",
            creationDate: iso8601.string(from: Date())
        )]
    }

    // MARK: - Redaction

    /// Replace a secret with `[redacted: N chars, KIND]` where KIND is
    /// numeric / alpha / alphanumeric / mixed. Empty/nil pass through.
    static func scrub(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return value }
        return "[redacted: \(value.count) chars, \(redactionKind(value))]"
    }

    private static func redactionKind(_ s: String) -> String {
        var hasDigit = false, hasAlpha = false, hasOther = false
        for c in s {
            if c.isLetter { hasAlpha = true }
            else if c.isNumber { hasDigit = true }
            else { hasOther = true }
        }
        if hasOther { return "mixed" }
        if hasDigit && hasAlpha { return "alphanumeric" }
        if hasDigit { return "numeric" }
        return "alpha"
    }

    /// Reverse of BitwardenJSONParser.pkcs8Base64ToPEM — strip PEM headers to get raw base64.
    static func pemToBase64(_ pem: String) -> String {
        pem.replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
           .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
           .components(separatedBy: .whitespacesAndNewlines)
           .joined()
    }
}

// MARK: - Bitwarden JSON Encodable Structs (private)

private struct ExportBWEnvelope: Encodable {
    let encrypted: Bool
    let folders: [ExportBWFolder]
    let items: [ExportBWItem]
}

private struct ExportBWFolder: Encodable {
    let id: String
    let name: String
}

private struct ExportBWItem: Encodable {
    let id: String
    let folderId: String?
    let type: Int
    let name: String
    let notes: String?
    let favorite: Bool
    let login: ExportBWLogin
}

private struct ExportBWLogin: Encodable {
    let username: String?
    let password: String?
    let totp: String?
    let uris: [ExportBWURI]
    let fido2Credentials: [ExportBWFido2Credential]?
}

private struct ExportBWURI: Encodable {
    let uri: String
}

private struct ExportBWFido2Credential: Encodable {
    let credentialId: String
    let keyType: String
    let keyAlgorithm: String
    let keyCurve: String
    let keyValue: String
    let rpId: String
    let rpName: String?
    let userHandle: String?
    let userName: String?
    let userDisplayName: String?
    let counter: String
    let discoverable: String
    let creationDate: String
}
