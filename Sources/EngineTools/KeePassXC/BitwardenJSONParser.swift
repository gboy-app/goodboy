// Parses Bitwarden JSON export format, extracting login items with
// optional fido2Credentials (passkeys).
//
// Maps to BoxItem with PasskeyExtrasKey extras for passkey data.
//
// Item types: 1=login, 2=secureNote, 3=card, 4=identity.
// Only type 1 (login) items are extracted — they may contain fido2Credentials.
//
// Critical encoding notes (from Bitwarden source code):
//    - keyValue: PKCS#8 DER encoded as **standard Base64** (RFC 4648 §4)
//    - credentialId: standard Base64
//    - userHandle: standard Base64 of opaque bytes
//    - counter: string representation of integer (not a number)
//    - discoverable: string "true" or "false" (not a boolean)

import Foundation
import FlowEngine

// MARK: - Bitwarden Export Models (Decodable)

/// Top-level Bitwarden export structure.
/// Supports both standard (folders/folderId) and Org (collections/collectionIds) formats.
struct BitwardenExport: Decodable {
    let encrypted: Bool
    let folders: [BitwardenFolder]?
    let collections: [BitwardenFolder]?
    let items: [BitwardenItem]
}

struct BitwardenFolder: Decodable {
    let id: String
    let name: String
}

struct BitwardenItem: Decodable {
    let id: String
    let folderId: String?
    let collectionIds: [String]?
    let type: Int                   // 1=login, 2=secureNote, 3=card, 4=identity
    let name: String
    let notes: String?
    let favorite: Bool?
    let login: BitwardenLogin?
}

struct BitwardenLogin: Decodable {
    let username: String?
    let password: String?
    let totp: String?
    let uris: [BitwardenURI]?
    let fido2Credentials: [BitwardenFido2Credential]?
}

struct BitwardenURI: Decodable {
    let uri: String?
}

struct BitwardenFido2Credential: Decodable {
    let credentialId: String        // standard Base64
    let keyType: String?            // "public-key"
    let keyAlgorithm: String?       // "ECDSA"
    let keyCurve: String?           // "P-256"
    let keyValue: String            // PKCS#8 DER in standard Base64
    let rpId: String
    let rpName: String?
    let userHandle: String?         // standard Base64
    let userName: String?
    let userDisplayName: String?
    let counter: String?            // string, not int
    let discoverable: String?       // string "true"/"false", not bool
    let creationDate: String?
}

// MARK: - Parser

public enum BitwardenJSONParser {

    /// Parse a Bitwarden JSON export string into BoxItems.
    /// Only extracts login items (type 1). Passkey data mapped to extras.
    public static func parse(json: String) throws -> [BoxItem] {
        guard let data = json.data(using: .utf8) else {
            throw KeePassError.jsonParseFailed("Invalid UTF-8 in Bitwarden JSON")
        }
        return try parse(data: data)
    }

    /// Parse Bitwarden JSON export data into BoxItems.
    public static func parse(data: Data) throws -> [BoxItem] {
        let export: BitwardenExport
        do {
            export = try JSONDecoder().decode(BitwardenExport.self, from: data)
        } catch {
            throw KeePassError.jsonParseFailed("Invalid Bitwarden JSON: \(error.localizedDescription)")
        }

        guard !export.encrypted else {
            throw KeePassError.jsonParseFailed("Encrypted Bitwarden exports are not supported. Export as unencrypted JSON.")
        }

        // Build folder lookup (standard: folders, Org: collections)
        var folderMap: [String: String] = [:]
        if let folders = export.folders {
            for folder in folders {
                folderMap[folder.id] = folder.name
            }
        }
        if let collections = export.collections {
            for collection in collections {
                folderMap[collection.id] = collection.name
            }
        }

        var credentials: [BoxItem] = []

        for item in export.items {
            // Only process login items (type 1)
            guard item.type == 1, let login = item.login else { continue }

            let url = login.uris?.first?.uri ?? ""
            let username = login.username ?? ""
            let password = login.password

            var extras: [String: String] = [:]

            // Title
            extras["title"] = item.name

            // Notes
            if let notes = item.notes, !notes.isEmpty {
                extras["notes"] = notes
            }

            // Folder (standard: folderId, Org: collectionIds[0])
            if let folderId = item.folderId, let folderName = folderMap[folderId] {
                extras["group"] = folderName
            } else if let collectionIds = item.collectionIds, let firstId = collectionIds.first,
                      let collectionName = folderMap[firstId] {
                extras["group"] = collectionName
            }

            // TOTP
            if let totp = login.totp, !totp.isEmpty {
                extras["otpAuth"] = totp
            }

            // Passkey (fido2Credentials — usually 0 or 1 per login)
            if let fido2Creds = login.fido2Credentials, let fido2 = fido2Creds.first {
                extras[PasskeyExtrasKey.rpId] = fido2.rpId
                extras[PasskeyExtrasKey.credentialId] = fido2.credentialId
                extras[PasskeyExtrasKey.username] = fido2.userName ?? username

                if let userHandle = fido2.userHandle {
                    extras[PasskeyExtrasKey.userHandle] = userHandle
                }

                // keyValue is PKCS#8 DER in standard Base64 — wrap as PEM for KPEX
                extras[PasskeyExtrasKey.privateKeyPEM] = pkcs8Base64ToPEM(fido2.keyValue)
            }

            credentials.append(BoxItem(
                url: url,
                username: username,
                password: password,
                extras: extras
            ))
        }

        return credentials
    }

    /// Convert a PKCS#8 DER key in standard Base64 to PEM format.
    /// KPEX expects `-----BEGIN PRIVATE KEY-----` wrapped PEM.
    static func pkcs8Base64ToPEM(_ base64: String) -> String {
        var lines = ["-----BEGIN PRIVATE KEY-----"]
        var remaining = base64
        while !remaining.isEmpty {
            let lineEnd = remaining.index(remaining.startIndex, offsetBy: min(64, remaining.count))
            lines.append(String(remaining[remaining.startIndex..<lineEnd]))
            remaining = String(remaining[lineEnd...])
        }
        lines.append("-----END PRIVATE KEY-----")
        return lines.joined(separator: "\n")
    }
}
