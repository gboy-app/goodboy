// Parses Proton Pass JSON/ZIP export format into BoxItems.
// Reuses existing models from ProtonPassCLI.swift: PPExport, PPVaultExport,
// PPItem, PPItemData, PPMetadata, PPContent, PPExtraField, PPExtraFieldData.
//
// Handles all 8 documented anomalies from PLAN-pass-import-formats.md.

import Foundation
import FlowEngine

public enum ProtonPassParser {

    /// Parse a Proton Pass JSON export (from ZIP or standalone) into BoxItems.
    /// Reuses PPExport model — same structure as the ZIP export JSON.
    public static func parse(data: Data) throws -> [BoxItem] {
        let export: PPExport
        do {
            export = try JSONDecoder().decode(PPExport.self, from: data)
        } catch {
            throw FileParseError.invalidStructure(
                "Invalid Proton Pass JSON: \(error.localizedDescription)")
        }

        guard !(export.encrypted ?? false) else {
            throw FileParseError.encrypted(
                "Encrypted Proton Pass exports are not supported. Export as unencrypted JSON from Proton Pass settings.")
        }

        var credentials: [BoxItem] = []

        for (_, vault) in export.vaults {
            let vaultName = vault.name

            for item in vault.items {
                // Anomaly #1: Exclude trashed items (state != 1)
                if let state = item.state, state != 1 { continue }

                // Anomaly #7/#8: Skip non-login items (note, alias, creditCard, password)
                guard item.data.type == "login" else { continue }

                let content = item.data.content
                let metadata = item.data.metadata

                // Anomaly #5: URLs are plain strings, take first
                let url = content.urls?.first ?? ""

                // Anomaly #2: Username fallback chain: itemUsername → itemEmail → ""
                let username: String
                if let itemUsername = content.itemUsername, !itemUsername.isEmpty {
                    username = itemUsername
                } else if let itemEmail = content.itemEmail, !itemEmail.isEmpty {
                    username = itemEmail
                } else {
                    username = ""
                }

                // Password: nil/empty → BoxItem(password: nil)
                let password: String?
                if let pw = content.password, !pw.isEmpty {
                    password = pw
                } else {
                    password = nil
                }

                var extras: [String: String] = [:]

                // Title
                extras["title"] = metadata.name

                // Notes
                if let note = metadata.note, !note.isEmpty {
                    extras["notes"] = note
                }

                // Vault name → group
                if !vaultName.isEmpty {
                    extras["group"] = vaultName
                }

                // Anomaly #3/#4: TOTP handling
                // First check content.totpUri, then scan extraFields for type=="totp"
                var totpUri: String? = nil
                if let uri = content.totpUri, !uri.isEmpty {
                    totpUri = uri
                }

                // Collect custom fields and hoist TOTP from extraFields
                var customFields: [[String: String]] = []
                if let extraFields = item.data.extraFields {
                    for field in extraFields {
                        if field.type == "totp" {
                            // Anomaly #3: Hoist TOTP from extraFields if content.totpUri is empty
                            // Anomaly #4: Uniform shape — data.content holds the value for all types
                            if totpUri == nil, let uri = field.data.content, !uri.isEmpty {
                                totpUri = uri
                            }
                            // Don't add TOTP fields to customFields
                        } else {
                            // Anomaly #6: Garbage fieldName values — store as-is
                            if let value = field.data.content, !value.isEmpty {
                                customFields.append([
                                    "name": field.fieldName,
                                    "type": field.type,
                                    "value": value,
                                ])
                            }
                        }
                    }
                }

                if let totp = totpUri {
                    extras["otpAuth"] = totp
                }

                if !customFields.isEmpty {
                    if let jsonData = try? JSONSerialization.data(
                        withJSONObject: customFields, options: [.sortedKeys]) {
                        extras["customFields"] = String(data: jsonData, encoding: .utf8)
                    }
                }

                credentials.append(BoxItem(
                    url: url,
                    username: username,
                    password: password,
                    extras: extras
                ))
            }
        }

        return credentials
    }
}
