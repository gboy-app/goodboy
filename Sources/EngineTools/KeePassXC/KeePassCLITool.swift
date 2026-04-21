// Merged Tool: Reads and writes credentials via `keepassxc-cli`.
//
// Read path: Full XML export including custom string fields (KPEX passkey attributes).
// Write path: Password-only entries use `keepassxc-cli add`. Passkey entries use the XML
// pipeline: generate KeePass XML → import to temp DB → merge into target.
// Requires dbPath + dbPassword params. Optional keyFile for key-file-protected databases.

import Foundation
import os.log
import FlowEngine

public final class KeePassCLITool: Tool {

    public static let id = "keepasscli"
    public static let name = "KeePassXC CLI"
    public static let description = "Reads and writes credentials via keepassxc-cli"
    public static let supportedTypes: [BoxItemType] = [.password, .otp, .passkey]

    public static let paramSchema: [ParamSpec] = [
        ParamSpec(key: "dbPath", label: "Database Path", type: .path, required: false,
                  description: "Path to the .kdbx database file. If omitted, auto-detects from KeePassXC's most recently opened database.",
                  editable: false),
        ParamSpec(key: "dbPassword", label: "Database Password", type: .keychain, required: true,
                  description: "Master password for the KeePassXC database"),
        ParamSpec(key: "keyFile", label: "Key File", type: .path, required: false,
                  description: "Path to an optional key file for the database"),
    ]

    public static var slugPool: [SlugEntry] {
        [
            SlugEntry(slug: "default", name: "KeePass CLI", config: [:]),
            SlugEntry(slug: "secondary", name: "KeePass CLI (2nd DB)", config: [:]),
        ]
    }

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "KeePassCLITool")

    public init() {}

    // MARK: - Capabilities

    public func canRead(slug: String) -> Bool { true }
    public func canWrite(slug: String) -> Bool { true }

    // MARK: - Data Schema

    public func dataSchema(params: [String: String]) -> [DataSchemaField] {
        [
            DataSchemaField(key: "url", type: "url", required: false),
            DataSchemaField(key: "username", type: "string", required: false),
            DataSchemaField(key: "password", type: "secret", required: false),
            DataSchemaField(key: "title", type: "string", required: false),
            DataSchemaField(key: "otpAuth", type: "secret", required: false),
            DataSchemaField(key: "passkey_rpId", type: "string", required: false),
            DataSchemaField(key: "passkey_credentialId", type: "string", required: false),
            DataSchemaField(key: "passkey_userHandle", type: "string", required: false),
            DataSchemaField(key: "passkey_userName", type: "string", required: false),
            DataSchemaField(key: "passkey_userDisplayName", type: "string", required: false),
            DataSchemaField(key: "passkey_key", type: "secret", required: false),
            DataSchemaField(key: "notes", type: "string", required: false),
            DataSchemaField(key: "group", type: "string", required: false),
        ]
    }

    // MARK: - Suggest Device Configs

    public func suggestDeviceConfigs() -> [[String: String]] {
        let slugs = Self.slugPool.map(\.slug)
        return KeePassCLI.detectAllDatabases().enumerated().map { idx, dbPath in
            let filename = (dbPath as NSString).lastPathComponent
            let slug: String
            if idx < slugs.count {
                slug = slugs[idx]
            } else {
                slug = "default-\(idx + 1)"
            }
            return [
                "dbPath": dbPath,
                "_name": "\(Self.name) (\(filename))",
                "_slug": slug,
                "_canRead": "true",
                "_canWrite": "true",
            ]
        }
    }

    // MARK: - Watched Files

    public func watchedFiles(params: [String: String]) -> [String] {
        guard let dbPath = params["dbPath"], !dbPath.isEmpty else { return [] }
        let expanded = NSString(string: dbPath).expandingTildeInPath
        return FileManager.default.fileExists(atPath: expanded) ? [expanded] : []
    }

    // MARK: - Discovery

    public func discover() -> [String: Any] {
        var result: [String: Any] = [:]
        if let binary = KeePassCLI.findBinary() {
            result["cliAvailable"] = true
            result["cliBinary"] = binary
        } else {
            result["cliAvailable"] = false
        }
        let dbs = KeePassCLI.detectAllDatabases()
        if !dbs.isEmpty {
            result["databases"] = dbs
        }
        return result
    }

    // MARK: - Device Availability

    /// Resolve dbPath: explicit param → auto-detect from KeePassXC → error.
    /// Explicit paths are rejected if they contain null bytes or resolve to
    /// a location containing `..` components (symlink bouncing upward).
    /// Matches the expand → standardize → resolveSymlinks order used by
    /// JSONExportPathPolicy so F1 stays in sync with the public SECURITY.md.
    private static func resolveDbPath(params: [String: String]) -> (path: String?, errors: [DeviceError]) {
        if let explicit = params["dbPath"], !explicit.isEmpty {
            if explicit.contains("\0") {
                return (nil, [DeviceError(category: .missingParam, message: "Database path must not contain null bytes.", action: "Select database")])
            }
            let expanded = (explicit as NSString).expandingTildeInPath
            let resolved = URL(fileURLWithPath: expanded).standardizedFileURL.resolvingSymlinksInPath().path
            if URL(fileURLWithPath: resolved).pathComponents.contains("..") {
                return (nil, [DeviceError(category: .missingParam, message: "Database path must not contain '..'.", action: "Select database")])
            }
            guard FileManager.default.fileExists(atPath: resolved) else {
                return (nil, [DeviceError(category: .resourceGone, message: "Database file not found at '\(explicit)'. Check the path and try again.", action: "Select database")])
            }
            return (resolved, [])
        }
        if let detected = KeePassCLI.detectDatabase() {
            return (detected, [])
        }
        return (nil, [DeviceError(category: .missingParam, message: "No database path provided and no recently opened database found in KeePassXC. Provide the path to your .kdbx file in device config, or open a database in KeePassXC first.", action: "Select database")])
    }

    // MARK: - Check + Connect

    public func check(params: [String: String]) -> [DeviceError] {
        if !KeePassCLI.isAvailable {
            return [DeviceError(category: .notInstalled, message: "KeePassXC not found. Click Install — uses Homebrew (brew install --cask keepassxc).", action: "Install KeePassXC", actionURL: "https://keepassxc.org")]
        }
        let resolved = Self.resolveDbPath(params: params)
        return resolved.errors
    }

    public func connect(params: [String: String]) throws {
        guard KeePassCLI.isAvailable else {
            throw ToolError("KeePassXC CLI not found. Install KeePassXC from keepassxc.org.")
        }
        let resolved = Self.resolveDbPath(params: params)
        guard let dbPath = resolved.path else {
            throw ToolError(resolved.errors.first?.message ?? "No database found.")
        }
        let password = (params["dbPassword"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !password.isEmpty else {
            throw ToolError("Database password is required.")
        }
        let keyFile = params["keyFile"]
        let valid = try KeePassCLI.dbInfo(dbPath: dbPath, password: password, keyFile: keyFile)
        if !valid {
            throw ToolError("Wrong database password or key file.")
        }
    }

    // MARK: - Execute

    public func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        switch action {
        case .read:
            return try await executeRead(params: params, securedBox: securedBox)
        case .write:
            return try await executeWrite(params: params, securedBox: securedBox)
        }
    }

    // MARK: - Read (Source)

    private func executeRead(params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        let resolved = Self.resolveDbPath(params: params)
        guard let dbPath = resolved.path else { return .failure(resolved.errors.first?.message ?? "Missing 'dbPath'.") }
        guard let dbPassword = params["dbPassword"] else { return .failure("Missing 'dbPassword'.") }
        let keyFile = params["keyFile"]

        // Fast-fail: verify credentials before attempting export.
        do {
            let valid = try KeePassCLI.dbInfo(dbPath: dbPath, password: dbPassword, keyFile: keyFile)
            if !valid {
                return .failure("Cannot open database — wrong password or key file. Re-enter via goodboy_keychain_set.")
            }
        } catch {
            return .failure("Cannot open database at '\(dbPath)': \(error.localizedDescription)")
        }

        // Export as XML (includes KPEX passkey attributes)
        let xmlString = try KeePassCLI.exportXML(dbPath: dbPath, password: dbPassword, keyFile: keyFile)

        // Parse XML
        let parser = KeePassXMLParser()
        let parsedEntries = try parser.parse(xml: xmlString)

        Self.log.info("Parsed \(parsedEntries.count) entries from XML export")

        // Convert to BoxItems
        let credentials = parsedEntries.map { $0.toBoxItem() }

        var warnings: [String] = []
        let passkeyCount = credentials.filter { $0.extras[PasskeyExtrasKey.rpId] != nil }.count
        if passkeyCount > 0 {
            warnings.append("\(passkeyCount) passkey entries found (with KPEX attributes)")
        }
        let otpCount = credentials.filter { $0.extras["otpAuth"] != nil }.count
        if otpCount > 0 {
            warnings.append("\(otpCount) entries with OTP")
        }

        securedBox.append(credentials)
        Self.log.info("Loaded \(credentials.count) credentials via CLI XML export")

        return .success(
            count: credentials.count,
            message: "Read \(credentials.count) credentials from KeePassXC via CLI export",
            warnings: warnings
        )
    }

    // MARK: - Write (Destination)

    private func executeWrite(params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        let items = securedBox.items
        guard !items.isEmpty else {
            return .success(count: 0, message: "No credentials to write")
        }

        let resolved = Self.resolveDbPath(params: params)
        guard let dbPath = resolved.path else { return .failure(resolved.errors.first?.message ?? "Missing 'dbPath'.") }
        guard let dbPassword = params["dbPassword"] else { return .failure("Missing 'dbPassword'.") }
        let keyFile = params["keyFile"]

        // Fast-fail: verify credentials before attempting any writes.
        // dbInfo() completes in <1s vs 30s timeout per addEntry() with wrong password.
        do {
            let valid = try KeePassCLI.dbInfo(dbPath: dbPath, password: dbPassword, keyFile: keyFile)
            if !valid {
                return .failure("Cannot open database — wrong password or key file. Re-enter via goodboy_keychain_set.")
            }
        } catch {
            return .failure("Cannot open database at '\(dbPath)': \(error.localizedDescription)")
        }
        let targetGroup = params["group"]

        // Partition: password-only vs passkey-containing
        let passwordItems = items.filter { $0.extras[PasskeyExtrasKey.rpId] == nil }
        let passkeyItems = items.filter { $0.extras[PasskeyExtrasKey.rpId] != nil }

        var savedCount = 0
        var warnings: [String] = []

        // Create target group if specified (mkdir is idempotent — errors if already exists)
        if let group = targetGroup, !group.isEmpty {
            do {
                try KeePassCLI.mkdir(dbPath: dbPath, password: dbPassword, group: group, keyFile: keyFile)
            } catch {
                // Ignore "already exists" — keepassxc-cli mkdir fails if group exists
                let msg = error.localizedDescription
                if !msg.contains("already exists") {
                    Self.log.warning("mkdir '\(group)' failed (may already exist): \(msg)")
                }
            }
        }

        // Password-only entries: use addEntry
        for item in passwordItems {
            let rawTitle = item.extras["title"] ?? item.url
            // keepassxc-cli treats "/" as group separators in the entry path.
            // Extract the domain from URLs to avoid creating bogus groups.
            let title: String
            if rawTitle.contains("/"), let host = URL(string: rawTitle)?.host {
                title = host
            } else {
                title = rawTitle
            }
            let url = item.url
            let login = item.username
            let password = item.password ?? ""

            // keepassxc-cli add needs an entry name — fall back if empty
            let entryTitle = !title.isEmpty ? title : (!login.isEmpty ? login : "Untitled")

            do {
                try KeePassCLI.addEntry(
                    dbPath: dbPath,
                    password: dbPassword,
                    title: entryTitle,
                    url: url,
                    username: login,
                    entryPassword: password,
                    group: targetGroup,
                    keyFile: keyFile
                )
                savedCount += 1
            } catch {
                warnings.append("Failed to add \(entryTitle): \(error.localizedDescription)")
            }
        }

        // Passkey entries: generate XML → import to temp DB → merge into target
        if !passkeyItems.isEmpty {
            do {
                let xmlString = KeePassXMLGenerator.generate(
                    credentials: passkeyItems,
                    groupName: targetGroup
                )

                // Create temp DB path for import
                let tmpDir = FileManager.default.temporaryDirectory
                let tmpDbPath = tmpDir.appendingPathComponent("goodboy-passkey-\(UUID().uuidString).kdbx").path

                defer {
                    try? FileManager.default.removeItem(atPath: tmpDbPath)
                }

                // Import XML into new temp DB
                try KeePassCLI.importXML(
                    dbPath: tmpDbPath,
                    password: dbPassword,
                    xmlString: xmlString,
                    keyFile: keyFile
                )

                // Merge temp DB into target
                try KeePassCLI.merge(
                    sourcePath: tmpDbPath,
                    destPath: dbPath,
                    password: dbPassword,
                    keyFile: keyFile
                )

                savedCount += passkeyItems.count
                Self.log.info("Imported \(passkeyItems.count) passkey entries via XML+merge")
            } catch {
                warnings.append("Passkey XML import failed: \(error.localizedDescription). Try importing passkeys separately.")
                warnings.append("\(passkeyItems.count) passkey entries were not written")
            }
        }

        Self.log.info("Added \(savedCount)/\(items.count) credentials via CLI")

        return .success(
            count: savedCount,
            message: "Wrote \(savedCount) credentials to KeePassXC via CLI",
            warnings: warnings
        )
    }
}
