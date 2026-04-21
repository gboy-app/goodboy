// Parses KeePassXC XML export format (standard KeePass XML).
// Extracts entries including custom string fields (KPEX passkey attributes),
// TOTP settings, and notes.
//
// Uses Foundation XMLParser (no external dependencies).
//
// KeePass XML structure:
//    <KeePassFile>
//      <Root>
//        <Group>
//          <Name>Root</Name>
//          <Entry>
//            <String><Key>Title</Key><Value>...</Value></String>
//            <String><Key>URL</Key><Value>...</Value></String>
//            <String><Key>UserName</Key><Value>...</Value></String>
//            <String><Key>Password</Key><Value ProtectInMemory="True">...</Value></String>
//            <String><Key>KPEX_PASSKEY_RELYING_PARTY</Key><Value>...</Value></String>
//            ...
//          </Entry>
//          <Group>...</Group>  (nested)
//        </Group>
//      </Root>
//    </KeePassFile>

import Foundation
import os.log
import FlowEngine

// MARK: - Parsed Entry

/// A fully parsed KeePassXC entry with all standard and custom fields.
public struct KeePassParsedEntry: Sendable {
    public let title: String
    public let url: String
    public let username: String
    public let password: String?
    public let notes: String?
    public let uuid: String
    public let groupPath: String           // e.g. "Root/Passwords"
    public let customFields: [String: String]  // Includes KPEX_PASSKEY_*, TOTP, etc.
    public let tags: [String]

    /// True if this entry has KPEX passkey attributes.
    public var hasPasskey: Bool {
        customFields[KPEXKey.relyingParty] != nil || customFields[KPEXKey.credentialID] != nil
    }

    /// Convert to BoxItem with KPEX → extras mapping.
    public func toBoxItem() -> BoxItem {
        var extras: [String: String] = [:]

        // Notes
        if let notes = notes, !notes.isEmpty {
            extras["notes"] = notes
        }

        // Group path
        if !groupPath.isEmpty {
            extras["group"] = groupPath
        }

        // Tags
        if !tags.isEmpty {
            extras["tags"] = tags.joined(separator: ",")
        }

        // KPEX passkey attributes → BoxItem passkey convention
        if let rp = customFields[KPEXKey.relyingParty] {
            extras[PasskeyExtrasKey.rpId] = rp
        }
        if let credId = customFields[KPEXKey.credentialID] {
            // KPEX stores as Base64Url; convert to standard Base64 for store convention
            extras[PasskeyExtrasKey.credentialId] = Base64Url.toBase64(credId)
        }
        if let userHandle = customFields[KPEXKey.userHandle] {
            extras[PasskeyExtrasKey.userHandle] = Base64Url.toBase64(userHandle)
        }
        if let privateKey = customFields[KPEXKey.privateKeyPEM] {
            extras[PasskeyExtrasKey.privateKeyPEM] = privateKey
        }
        if let pkUsername = customFields[KPEXKey.username] {
            extras[PasskeyExtrasKey.username] = pkUsername
        }

        // TOTP (KeePassXC stores as otpauth:// URI or TOTP seed)
        if let totp = customFields["otp"], !totp.isEmpty {
            extras["otpAuth"] = totp
        }
        if let totp = customFields["TOTP Seed"], !totp.isEmpty {
            extras["otpAuth"] = totp
        }
        if let totp = customFields["TOTP Settings"], !totp.isEmpty {
            extras["otpSettings"] = totp
        }

        // Remaining custom fields that aren't KPEX or TOTP
        for (key, value) in customFields {
            if key.hasPrefix("KPEX_") { continue }
            if key == "otp" || key.hasPrefix("TOTP") { continue }
            if key == "HmacOtp-Secret" || key == "HmacOtp-Counter" { continue }
            extras["custom_\(key)"] = value
        }

        return BoxItem(
            url: url,
            username: username,
            password: password,
            extras: extras
        )
    }
}

// MARK: - XML Parser

public final class KeePassXMLParser: NSObject, XMLParserDelegate {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "KeePassXMLParser")

    // MARK: - Parse result
    private var entries: [KeePassParsedEntry] = []
    private var parseError: Error?

    // MARK: - Parser state
    private var groupStack: [String] = []       // Track current group nesting
    private var groupUUIDStack: [String] = []   // Parallel UUID stack for groups
    private var inEntry = false
    private var inString = false
    private var inAutoType = false
    private var currentKey = ""
    private var currentValue = ""
    private var currentElement = ""
    private var entryFields: [String: String] = [:]
    private var entryUUID = ""
    private var entryTags: [String] = []
    private var inTags = false
    private var recycleBinUUID = ""
    private var recycleBinGroupUUIDs: Set<String> = []
    private var currentGroupUUID = ""
    private var inDeletedObjects = false

    // Standard KeePass entry fields
    private static let standardKeys: Set<String> = ["Title", "URL", "UserName", "Password", "Notes"]

    // MARK: - Public API

    /// Parse a KeePass XML string and return all non-recycled entries.
    public func parse(xml: String) throws -> [KeePassParsedEntry] {
        guard let data = xml.data(using: .utf8) else {
            throw KeePassError.xmlParseFailed("Invalid UTF-8")
        }
        return try parse(data: data)
    }

    /// Parse KeePass XML data and return all non-recycled entries.
    public func parse(data: Data) throws -> [KeePassParsedEntry] {
        entries = []
        parseError = nil
        groupStack = []
        groupUUIDStack = []
        recycleBinUUID = ""
        recycleBinGroupUUIDs = []
        inDeletedObjects = false

        let parser = XMLParser(data: data)
        parser.delegate = self
        parser.parse()

        if let error = parseError {
            throw error
        }
        if let error = parser.parserError {
            throw KeePassError.xmlParseFailed(error.localizedDescription)
        }

        Self.log.info("Parsed \(self.entries.count) entries from XML")
        return entries
    }

    // MARK: - XMLParserDelegate

    public func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
        currentElement = elementName

        switch elementName {
        case "Group":
            if inDeletedObjects { return }
            groupStack.append("")
            groupUUIDStack.append("")
            currentGroupUUID = ""

        case "Entry":
            if inDeletedObjects { return }
            inEntry = true
            entryFields = [:]
            entryUUID = ""
            entryTags = []

        case "String":
            if inEntry {
                inString = true
                currentKey = ""
                currentValue = ""
            }

        case "AutoType":
            inAutoType = true

        case "Tags":
            if inEntry {
                inTags = true
            }

        case "DeletedObjects":
            inDeletedObjects = true

        default:
            break
        }
    }

    public func parser(_ parser: XMLParser, foundCharacters string: String) {
        if inDeletedObjects { return }

        if inAutoType { return }

        if inString && inEntry {
            if currentElement == "Key" {
                currentKey += string
            } else if currentElement == "Value" {
                currentValue += string
            }
        } else if currentElement == "Name" && !groupStack.isEmpty && !inEntry {
            // Group name
            let idx = groupStack.count - 1
            groupStack[idx] = groupStack[idx] + string
        } else if currentElement == "UUID" && !inEntry && !groupStack.isEmpty {
            currentGroupUUID += string
            let idx = groupUUIDStack.count - 1
            if idx >= 0 { groupUUIDStack[idx] = groupUUIDStack[idx] + string }
        } else if currentElement == "UUID" && inEntry {
            entryUUID += string
        } else if inTags && currentElement == "Tag" {
            entryTags.append(string.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        // Capture RecycleBin UUID from Meta section
        if currentElement == "RecycleBinUUID" {
            recycleBinUUID += string
        }
    }

    public func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName: String?) {
        if elementName == "DeletedObjects" {
            inDeletedObjects = false
            return
        }
        if inDeletedObjects { return }

        switch elementName {
        case "Group":
            // Check if this group is the recycle bin
            if !currentGroupUUID.isEmpty && currentGroupUUID == recycleBinUUID {
                recycleBinGroupUUIDs.insert(currentGroupUUID)
            }
            if !groupStack.isEmpty {
                groupStack.removeLast()
            }
            if !groupUUIDStack.isEmpty {
                groupUUIDStack.removeLast()
            }
            currentGroupUUID = ""

        case "Entry":
            if inEntry {
                // Skip entries in recycle bin (by UUID or name)
                let isRecycledByUUID = !recycleBinGroupUUIDs.isEmpty && groupUUIDStack.contains { uuid in
                    recycleBinGroupUUIDs.contains(uuid)
                }
                let isRecycled = isRecycledByUUID || groupStack.contains { groupName in
                    groupName == "Recycle Bin" || groupName == "Trash"
                }

                if !isRecycled {
                    let groupPath = groupStack.joined(separator: "/")

                    // Separate standard fields from custom fields
                    var customFields: [String: String] = [:]
                    for (key, value) in entryFields {
                        if !Self.standardKeys.contains(key) {
                            customFields[key] = value
                        }
                    }

                    let entry = KeePassParsedEntry(
                        title: entryFields["Title"] ?? "",
                        url: entryFields["URL"] ?? "",
                        username: entryFields["UserName"] ?? "",
                        password: entryFields["Password"],
                        notes: entryFields["Notes"],
                        uuid: entryUUID.trimmingCharacters(in: .whitespacesAndNewlines),
                        groupPath: groupPath,
                        customFields: customFields,
                        tags: entryTags
                    )
                    entries.append(entry)
                }

                inEntry = false
            }

        case "String":
            if inString && inEntry {
                let key = currentKey.trimmingCharacters(in: .whitespacesAndNewlines)
                let value = currentValue.trimmingCharacters(in: .whitespacesAndNewlines)
                if !key.isEmpty {
                    entryFields[key] = value
                }
                inString = false
            }

        case "AutoType":
            inAutoType = false

        case "Tags":
            inTags = false

        default:
            break
        }

        currentElement = ""
    }

    public func parser(_ parser: XMLParser, parseErrorOccurred parseErr: Error) {
        parseError = KeePassError.xmlParseFailed(parseErr.localizedDescription)
    }
}
