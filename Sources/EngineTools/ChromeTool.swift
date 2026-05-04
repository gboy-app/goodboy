// Merged Tool: Reads and writes passwords for Chromium browsers.
//
// Reading: Reads credentials from Chrome's local SQLite database.
// Chrome stores passwords at: ~/Library/Application Support/Google/Chrome/Default/Login Data
// Passwords are encrypted with Chrome Safe Storage keychain item.
//
// Writing: Direct mode — writes to the real profile database.
// Chrome must be closed. User reopens Chrome to sync.
// Target table auto-detected from syncMode (LDFA for accountStorage/both,
// Login Data for chromeSync). Empty profiles (no Google account) refused.

import Foundation
import SQLite3
import CommonCrypto
import CryptoKit
import os.log
import FlowEngine

// MARK: - Chrome PT

public final class ChromeTool: Tool {

    // MARK: - Tool Protocol

    public static let id = "chrome"
    public static let name = "Chrome"
    public static let description = "Reads and writes passwords for Chromium browsers"
    public static let supportedTypes: [BoxItemType] = [.password]


    public static var paramSchema: [ParamSpec] {
        [
            ParamSpec(key: "profile", label: "Chrome Profile", type: .string, required: true,
                      description: "Chrome profile folder, email, or name (e.g. Default, Profile 2, user@gmail.com)",
                      editable: false),
            ParamSpec(key: "chromeDir", label: "Browser Data Dir", type: .path, required: false,
                      description: "Path to Chromium browser data directory. Defaults to Chrome.",
                      editable: false),
            ParamSpec(key: "safeStorageKey", label: "Browser Encryption Key", type: .keychain, required: true,
                      description: "AES key derived from browser's Safe Storage keychain entry"),
        ]
    }

    /// Chrome profile slugs can read and write. Other browser slugs can only read.
    private static let chromeProfileSlugs: Set<String> = ["default", "secondary", "tertiary", "quaternary"]

    public static var slugPool: [SlugEntry] {
        let chromeProfileEntries: [SlugEntry] = [
            SlugEntry(slug: "default", name: "Chrome", config: ["profile": "Default"]),
            SlugEntry(slug: "secondary", name: "Chrome (2nd profile)", config: ["profile": "Profile 1"]),
            SlugEntry(slug: "tertiary", name: "Chrome (3rd profile)", config: ["profile": "Profile 2"]),
            SlugEntry(slug: "quaternary", name: "Chrome (4th profile)", config: ["profile": "Profile 3"]),
        ]
        let otherBrowserEntries: [SlugEntry] = ChromeHelper.knownChromiumBrowsers.map { browser in
            SlugEntry(slug: browser.slug, name: browser.name,
                      config: ["profile": "Default", "chromeDir": browser.dataDir])
        }
        return chromeProfileEntries + otherBrowserEntries
    }

    // MARK: - Capabilities

    public func canRead(slug: String) -> Bool {
        true  // All slugs (Chrome profiles + other browsers) can be read
    }

    public func canWrite(slug: String) -> Bool {
        Self.chromeProfileSlugs.contains(slug)  // Only Chrome profiles, not other browsers
    }

    // MARK: - Schema

    public func dataSchema(params: [String: String]) -> [DataSchemaField] {
        [
            DataSchemaField(key: "url", type: "url", required: true),
            DataSchemaField(key: "username", type: "string", required: true),
            DataSchemaField(key: "password", type: "secret", required: true),
        ]
    }

    // MARK: - Display name

    /// Pick the most user-recognizable label for a profile, in order:
    /// signed-in Google email → Chrome's local profile name → on-disk
    /// folder ("Profile 1", "Default") → the raw `profile` param the user
    /// typed. Each candidate is treated as missing when empty, not just
    /// nil — Chrome leaves `name = ""` on a brand-new profile that's
    /// never been signed into Google, which would otherwise render error
    /// messages like "Profile '' has no Google account."
    private static func displayName(resolved: ChromeProfileInfo?, query: String) -> String {
        if let email = resolved?.email, !email.isEmpty { return email }
        if let name = resolved?.name, !name.isEmpty { return name }
        if let folder = resolved?.folder, !folder.isEmpty { return folder }
        return query
    }

    // MARK: - Check + Connect

    public func check(params: [String: String]) -> [DeviceError] {
        let chromeDir = params["chromeDir"] ?? ChromeHelper.defaultChromeDir
        let isDefaultChrome = chromeDir == ChromeHelper.defaultChromeDir

        // Binary / data dir check
        if isDefaultChrome {
            guard ChromeHelper.isChromeInstalled() else {
                return [DeviceError(category: .notInstalled, message: "Chrome not found. Install Google Chrome and sign in to sync passwords.", action: "Install Chrome", actionURL: "https://google.com/chrome")]
            }
        }
        guard FileManager.default.fileExists(atPath: chromeDir) else {
            return [DeviceError(category: .notInstalled, message: "Browser data directory not found at '\(chromeDir)'. Launch the browser once to create it.", action: "Launch browser")]
        }

        var errors: [DeviceError] = []

        guard let profileQuery = params["profile"], !profileQuery.isEmpty else {
            errors.append(DeviceError(category: .missingParam, message: "Missing 'profile' param. Run goodboy_chrome_profiles to find yours.", action: "Select profile"))
            return errors
        }

        let resolved = try? ChromeHelper.resolveProfile(query: profileQuery, chromeDir: chromeDir)
        let profileFolder = resolved?.folder ?? profileQuery
        let profileName = Self.displayName(resolved: resolved, query: profileQuery)
        let profileDir = "\(chromeDir)/\(profileFolder)"

        guard FileManager.default.fileExists(atPath: profileDir) else {
            errors.append(DeviceError(category: .resourceGone, message: "Chrome profile '\(profileName)' not found. Run goodboy_chrome_profiles to see available profiles.", action: "Select profile"))
            return errors
        }

        let hasLoginData = FileManager.default.fileExists(atPath: "\(profileDir)/Login Data")
        let hasLDFA = FileManager.default.fileExists(atPath: "\(profileDir)/Login Data For Account")
        if !hasLoginData && !hasLDFA {
            errors.append(DeviceError(category: .notRunning, message: "No password database found for profile '\(profileName)'. Open Chrome with this profile once to initialize it.", action: "Open Chrome"))
        }

        if isDefaultChrome {
            let syncMode = ChromeHelper.detectSyncMode(folder: profileFolder, chromeDir: chromeDir)
            if syncMode == .empty {
                errors.append(DeviceError(category: .authFailed, message: "Profile '\(profileName)' has no Google account. Sign into Google in Chrome first — otherwise passwords can't sync.", action: "Sign into Google"))
            } else {
                let targetTable = (syncMode == .chromeSync) ? "Login Data" : "Login Data For Account"
                if !FileManager.default.fileExists(atPath: "\(profileDir)/\(targetTable)") {
                    errors.append(DeviceError(category: .notRunning, message: "Database '\(targetTable)' missing for profile '\(profileName)'. Open Chrome with this profile once to initialize the password database.", action: "Open Chrome"))
                }
            }
        }

        if params["safeStorageKey"] == nil {
            errors.append(DeviceError(category: .authFailed, message: "Browser not connected. Click Connect to authorize.", action: "Connect"))
        }

        return errors
    }

    public func connect(params: [String: String]) throws {
        guard let keyB64 = params["safeStorageKey"], !keyB64.isEmpty else {
            throw ToolError("Browser not connected. Click Connect to extract the encryption key.")
        }
        guard Self.decodeKey(keyB64) != nil else {
            throw ToolError("Invalid browser encryption key. Disconnect and reconnect.")
        }
    }

    // MARK: - Discovery

    public func discover() -> [String: Any] {
        guard ChromeHelper.isChromeInstalled() else { return ["installed": false] }
        guard let profiles = try? ChromeHelper.listProfiles() else { return ["installed": true] }
        return [
            "installed": true,
            "profiles": profiles.map { p in
                let syncMode = ChromeHelper.detectSyncMode(folder: p.folder)
                let stats = ChromeHelper.profileStats(folder: p.folder)
                return [
                    "folder": p.folder,
                    "name": p.name,
                    "email": p.email ?? "",
                    "syncMode": syncMode.rawValue,
                    "loginDataLogins": stats.loginDataLogins,
                    "ldfaLogins": stats.ldfaLogins,
                ] as [String: Any]
            }
        ]
    }

    public func normalizeConfig(_ config: [String: String]) -> [String: String] {
        var normalized = config
        let chromeDir = config["chromeDir"] ?? ChromeHelper.defaultChromeDir
        if let profile = config["profile"],
           let resolved = try? ChromeHelper.resolveProfile(query: profile, chromeDir: chromeDir) {
            normalized["profile"] = resolved.folder
        }
        return normalized
    }

    public func watchedFiles(params: [String: String]) -> [String] {
        ChromeHelper.watchedFiles(params: params)
    }

    public func credentialCount(params: [String: String]) -> Int? {
        guard let profileQuery = params["profile"], !profileQuery.isEmpty else { return nil }
        let chromeDir = params["chromeDir"] ?? ChromeHelper.defaultChromeDir
        let folder = (try? ChromeHelper.resolveProfile(query: profileQuery, chromeDir: chromeDir))?.folder ?? profileQuery
        let stats = ChromeHelper.profileStats(folder: folder, chromeDir: chromeDir)
        let total = stats.loginDataLogins + stats.ldfaLogins
        return total > 0 ? total : nil
    }

    // MARK: - Suggest Device Configs

    public func suggestDeviceConfigs() -> [[String: String]] {
        var suggestions: [[String: String]] = []

        // Chrome profiles
        if ChromeHelper.isChromeInstalled() {
            if let profiles = try? ChromeHelper.listProfiles() {
                let slots = ["default", "secondary", "tertiary", "quaternary"]
                let fm = FileManager.default

                suggestions += profiles.compactMap { p -> (String, String, String, Bool)? in
                    let profileDir = "\(ChromeHelper.defaultChromeDir)/\(p.folder)"
                    let hasDB = fm.fileExists(atPath: "\(profileDir)/Login Data")
                        || fm.fileExists(atPath: "\(profileDir)/Login Data For Account")
                    guard hasDB else { return nil }
                    let label = p.email ?? p.name
                    let hasGoogleAccount = p.email != nil && !p.email!.isEmpty
                    return (p.folder, label, p.name, hasGoogleAccount)
                }
                .enumerated()
                .map { idx, tuple in
                    let slug = idx < slots.count ? slots[idx] : "profile\(idx)"
                    return [
                        "profile": tuple.0,
                        "_name": "Chrome (\(tuple.1))",
                        "_slug": slug,
                        "_canRead": "true",
                        "_canWrite": tuple.3 ? "true" : "false",
                        "_profileName": tuple.2,
                    ]
                }
            }
        }

        // Other Chromium browsers (read-only)
        let appSupport = NSString(string: "~/Library/Application Support").expandingTildeInPath
        for browser in ChromeHelper.knownChromiumBrowsers {
            let browserDir = "\(appSupport)/\(browser.dataDir)"
            let dbPath = "\(browserDir)/Default/Login Data"
            guard FileManager.default.fileExists(atPath: dbPath) else { continue }
            suggestions.append([
                "profile": "Default",
                "chromeDir": browserDir,
                "_name": browser.name,
                "_slug": browser.slug,
                "_canRead": "true",
                "_canWrite": "false",
            ])
        }

        return suggestions
    }

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "ChromeTool")

    public init() {}

    // MARK: - Execute

    public func execute(action: ToolAction, params: [String: String],
                        securedBox: SecuredBox) async throws -> ToolResult {
        switch action {
        case .read:
            return try executeRead(params: params, securedBox: securedBox)
        case .write:
            return try await executeWrite(params: params, securedBox: securedBox)
        }
    }

    // MARK: - Read Execution

    private func executeRead(params: [String: String], securedBox: SecuredBox) throws -> ToolResult {
        guard let profile = params["profile"] else { return .failure("Missing 'profile'.") }
        guard let keyB64 = params["safeStorageKey"],
              let aesKey = Self.decodeKey(keyB64) else {
            return .failure("Missing or invalid browser encryption key. Authorize browser access first.")
        }
        let chromeDir = params["chromeDir"] ?? ChromeHelper.defaultChromeDir

        do {
            let credentials = try readChromePasswords(profile: profile, filter: nil, aesKey: aesKey, chromeDir: chromeDir)
            securedBox.append(credentials)
            return .success(count: credentials.count, message: "Loaded \(credentials.count) passwords from Chrome profile '\(profile)'")
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    // MARK: - Write Execution

    private func executeWrite(params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        guard !securedBox.isEmpty else {
            return .failure("No credentials in SecuredBox")
        }

        guard let profileQuery = params["profile"] else { return .failure("Missing 'profile'.") }
        let chromeDir = params["chromeDir"] ?? ChromeHelper.defaultChromeDir
        let resolved = try? ChromeHelper.resolveProfile(query: profileQuery, chromeDir: chromeDir)
        let profileFolder = resolved?.folder ?? profileQuery
        let profileName = Self.displayName(resolved: resolved, query: profileQuery)

        let syncMode = ChromeHelper.detectSyncMode(folder: profileFolder, chromeDir: chromeDir)

        guard syncMode != .empty else {
            return .failure("Profile '\(profileName)' has no Google account. Sign into Google in Chrome first.")
        }

        guard let keyB64 = params["safeStorageKey"],
              let aesKey = Data(base64Encoded: keyB64) else {
            return .failure("Missing or invalid browser encryption key. Authorize browser access first.")
        }

        let autoRelaunch = params["autoRelaunch"] == "true"

        do {
            return try await executeDirect(
                profileFolder: profileFolder, profileName: profileName,
                syncMode: syncMode, aesKey: aesKey, securedBox: securedBox,
                chromeDir: chromeDir, autoRelaunch: autoRelaunch
            )
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    // MARK: - Chrome Database Reading

    private func readChromePasswords(profile: String, filter: String?, aesKey: Data, chromeDir: String = ChromeHelper.defaultChromeDir) throws -> [BoxItem] {
        Self.log.info("Reading Chrome passwords, profile: \(profile), filter: \(filter ?? "none")")

        // Resolve profile — accepts folder name, email, or display name
        let profileFolder: String
        if let resolved = try? ChromeHelper.resolveProfile(query: profile, chromeDir: chromeDir) {
            profileFolder = resolved.folder
        } else {
            profileFolder = profile
        }

        // Detect which table has data (prefers Login Data For Account)
        let activeTable = ChromeHelper.detectActiveTable(folder: profileFolder, chromeDir: chromeDir) ?? "Login Data"
        let chromeDataPath = "\(chromeDir)/\(profileFolder)/\(activeTable)"

        guard FileManager.default.fileExists(atPath: chromeDataPath) else {
            throw ChromeToolError.notFound("'\(activeTable)' not found for Chrome profile '\(profileFolder)'. Check the profile name at chrome://version.")
        }

        // Chrome locks the database, so we need to copy it first
        let tempPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("chrome_login_data_\(UUID().uuidString).db")
            .path

        try FileManager.default.copyItem(atPath: chromeDataPath, toPath: tempPath)
        defer { try? FileManager.default.removeItem(atPath: tempPath) }

        let key = aesKey

        // Open SQLite database
        var db: OpaquePointer?
        guard sqlite3_open_v2(tempPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to open Chrome database")
        }
        defer { sqlite3_close(db) }

        // Query logins
        let query: String
        if let filter = filter, !filter.isEmpty {
            query = "SELECT origin_url, username_value, password_value FROM logins WHERE origin_url LIKE ? OR username_value LIKE ?"
        } else {
            query = "SELECT origin_url, username_value, password_value FROM logins"
        }

        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to prepare query")
        }
        defer { sqlite3_finalize(statement) }

        // Bind filter parameters if present (SQLITE_TRANSIENT copies the string)
        if let filter = filter, !filter.isEmpty {
            let likePattern = "%\(filter)%"
            let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            sqlite3_bind_text(statement, 1, likePattern, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(statement, 2, likePattern, -1, SQLITE_TRANSIENT)
        }

        var credentials: [BoxItem] = []

        while sqlite3_step(statement) == SQLITE_ROW {
            guard let urlPtr = sqlite3_column_text(statement, 0) else { continue }
            let url = String(cString: urlPtr)
            let username: String
            if let usernamePtr = sqlite3_column_text(statement, 1) {
                username = String(cString: usernamePtr)
            } else {
                username = ""
            }

            // Password is encrypted blob
            let passwordBlob = sqlite3_column_blob(statement, 2)
            let passwordLen = sqlite3_column_bytes(statement, 2)

            var password: String? = nil
            if let blob = passwordBlob, passwordLen > 0 {
                let data = Data(bytes: blob, count: Int(passwordLen))
                password = decryptChromePassword(data, key: key)
            }

            credentials.append(BoxItem(
                url: url,
                username: username,
                password: password,
                extras: [:]
            ))
        }

        Self.log.info("Found \(credentials.count) credentials in Chrome")
        return credentials
    }

    /// Decode the base64 AES key from resolved params.
    private static func decodeKey(_ b64: String) -> Data? {
        Data(base64Encoded: b64)
    }

    /// Decrypt a Chrome password blob (read path)
    private func decryptChromePassword(_ encrypted: Data, key: Data) -> String? {
        // Chrome uses "v10" prefix for encrypted passwords
        guard encrypted.count > 3 else { return nil }

        let prefix = String(data: encrypted.prefix(3), encoding: .utf8)

        if prefix == "v10" {
            let payload = encrypted.dropFirst(3)

            // macOS Chrome uses AES-128-CBC with 16-byte space IV (0x20)
            // This produces payloads that are multiples of 16 bytes
            if payload.count > 0 && payload.count <= 256 && payload.count % 16 == 0 {
                if let result = decryptAESCBC(ciphertext: Data(payload), key: key) {
                    return result
                }
            }

            // Windows/Linux Chrome v80+ uses AES-GCM: 12-byte nonce + ciphertext + 16-byte tag
            if payload.count > 28 {
                let nonce = payload.prefix(12)
                let ciphertextWithTag = payload.dropFirst(12)
                if let result = decryptAESGCM(ciphertext: Data(ciphertextWithTag), key: key, nonce: Data(nonce)) {
                    return result
                }
            }
        }

        return nil
    }

    /// AES-CBC decryption with 16-byte space IV (macOS Chrome format)
    private func decryptAESCBC(ciphertext: Data, key: Data) -> String? {
        let iv = [UInt8](repeating: 0x20, count: 16) // 16 spaces
        var decrypted = [UInt8](repeating: 0, count: ciphertext.count + 16)
        var decryptedLen: size_t = 0

        let status = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            [UInt8](key), key.count,
            iv,
            [UInt8](ciphertext), ciphertext.count,
            &decrypted, decrypted.count,
            &decryptedLen
        )

        guard status == kCCSuccess else { return nil }
        return String(data: Data(decrypted.prefix(decryptedLen)), encoding: .utf8)
    }

    /// AES-GCM decryption using CryptoKit
    private func decryptAESGCM(ciphertext: Data, key: Data, nonce: Data) -> String? {
        guard ciphertext.count > 16 else { return nil }

        let actualCiphertext = ciphertext.dropLast(16)
        let tag = ciphertext.suffix(16)

        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: actualCiphertext,
                tag: tag
            )
            let symmetricKey = SymmetricKey(data: key)
            let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
            return String(data: decrypted, encoding: .utf8)
        } catch {
            return nil
        }
    }

    // MARK: - Direct Write (Chrome must be closed)

    /// Write directly to the real profile database. Chrome must be closed.
    /// User opens Chrome afterwards to sync.
    private func executeDirect(
        profileFolder: String, profileName: String,
        syncMode: ChromeSyncMode,
        aesKey: Data, securedBox: SecuredBox,
        chromeDir: String, autoRelaunch: Bool = false
    ) async throws -> ToolResult {
        var didQuitChrome = false
        if ChromeHelper.isChromeRunning() {
            if autoRelaunch {
                Self.log.info("Auto-relaunch: quitting Chrome")
                guard await ChromeHelper.quitChrome() else {
                    return .failure("Could not quit Chrome. Close it manually and try again.")
                }
                didQuitChrome = true
            } else {
                return .failure(
                    "Close Chrome and try again."
                )
            }
        }

        let targetTable = (syncMode == .chromeSync) ? "Login Data" : "Login Data For Account"
        let profileDir = "\(chromeDir)/\(profileFolder)"
        let dbPath = "\(profileDir)/\(targetTable)"
        Self.log.info("Direct DB: \(targetTable) for '\(profileName)'")

        let result = try upsertAll(dbPath: dbPath, aesKey: aesKey, securedBox: securedBox)

        guard result.writtenCount > 0 else {
            return .failure("No credentials to write (all skipped)")
        }

        Self.log.info("Direct: \(result.inserted) inserted, \(result.updated) updated")

        if didQuitChrome {
            ChromeHelper.launchChrome()
            Self.log.info("Auto-relaunch: reopening Chrome")
        }

        let suffix = didQuitChrome ? " Chrome is reopening." : " Open Chrome to sync."
        return .success(
            count: result.writtenCount,
            message: "Wrote \(result.writtenCount) passwords to '\(profileName)'"
                + " (\(result.breakdown))." + suffix,
            warnings: result.warnings
        )
    }


    // MARK: - Upsert

    private struct UpsertResult {
        var ids: [Int64] = []
        var inserted = 0
        var updated = 0
        var skippedDuplicates = 0
        var warnings: [String] = []
        var total: Int { inserted + updated + skippedDuplicates }
        var writtenCount: Int { inserted + updated }

        /// e.g. "3 new, 1 updated" or "2 new, 1 already existed"
        var breakdown: String {
            var parts: [String] = []
            if inserted > 0 { parts.append("\(inserted) new") }
            if updated > 0 { parts.append("\(updated) updated") }
            if skippedDuplicates > 0 { parts.append("\(skippedDuplicates) already existed") }
            return parts.joined(separator: ", ")
        }
    }

    private func upsertAll(dbPath: String, aesKey: Data,
                           securedBox: SecuredBox) throws -> UpsertResult {
        var result = UpsertResult()

        for item in securedBox.items {
            guard let password = item.password, !password.isEmpty else {
                result.warnings.append("Skipped \(item.url): no password")
                continue
            }

            let url = normalizeURL(item.url)
            let realm = originRealm(url)

            if let existingID = try findExistingLoginID(
                dbPath: dbPath, url: url,
                username: item.username, realm: realm
            ) {
                try updateOne(
                    dbPath: dbPath, aesKey: aesKey, loginID: existingID,
                    url: url, username: item.username,
                    password: password, realm: realm
                )
                result.ids.append(existingID)
                result.updated += 1
                Self.log.info("Updated: \(url) (id=\(existingID))")
            } else {
                let newID = try injectOne(
                    dbPath: dbPath, aesKey: aesKey,
                    url: url, username: item.username,
                    password: password, realm: realm
                )
                if newID == -1 {
                    // UNIQUE constraint caught a duplicate that findExistingLoginID
                    // missed (Chrome sync may have modified the URL format)
                    result.skippedDuplicates += 1
                    Self.log.info("Already exists (URL mismatch): \(url)")
                } else {
                    result.ids.append(newID)
                    result.inserted += 1
                    Self.log.info("Inserted: \(url) (id=\(newID))")
                }
            }
        }

        return result
    }

    // MARK: - Find Existing

    /// Find an existing login by URL + username. Uses RTRIM to tolerate trailing
    /// slash differences — Chrome sync may strip or add trailing slashes after
    /// a round-trip through Google.
    private func findExistingLoginID(dbPath: String, url: String,
                                     username: String,
                                     realm: String) throws -> Int64? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK
        else {
            throw ChromeToolError.databaseError("Failed to open DB for lookup")
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        let sql = """
            SELECT id FROM logins
            WHERE RTRIM(origin_url, '/') = RTRIM(?1, '/')
              AND username_value = ?2
              AND RTRIM(signon_realm, '/') = RTRIM(?3, '/')
            """
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to prepare lookup")
        }
        defer { sqlite3_finalize(stmt) }

        let TR = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, url, -1, TR)
        sqlite3_bind_text(stmt, 2, username, -1, TR)
        sqlite3_bind_text(stmt, 3, realm, -1, TR)

        if sqlite3_step(stmt) == SQLITE_ROW {
            return sqlite3_column_int64(stmt, 0)
        }
        return nil
    }

    // MARK: - Read Metadata

    private func readMetadata(dbPath: String, loginID: Int64,
                              aesKey: Data) throws -> [Int: Any]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK
        else {
            throw ChromeToolError.databaseError(
                "Failed to open DB for metadata read"
            )
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        let sql = "SELECT metadata FROM sync_entities_metadata WHERE storage_key=?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK
        else { return nil }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, loginID)

        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

        let blobPtr = sqlite3_column_blob(stmt, 0)
        let blobLen = sqlite3_column_bytes(stmt, 0)
        guard let ptr = blobPtr, blobLen > 0 else { return nil }

        let encrypted = Data(bytes: ptr, count: Int(blobLen))
        let decrypted = try v10Decrypt(encrypted, key: aesKey)
        return decodeMetadata(decrypted)
    }

    // MARK: - Update

    /// Update an existing credential's password and mark metadata dirty for sync.
    private func updateOne(dbPath: String, aesKey: Data, loginID: Int64,
                           url: String, username: String,
                           password: String, realm: String) throws {
        let encryptedPw = try v10Encrypt(Data(password.utf8), key: aesKey)
        let now = webkitTimestamp()
        let tsMs = unixMs()

        // Read existing metadata (may be nil for orphan/unsynced entries)
        let existingFields = try readMetadata(
            dbPath: dbPath, loginID: loginID, aesKey: aesKey
        )

        let encryptedMeta: Data
        let hasExistingMeta = existingFields != nil

        if let fields = existingFields {
            // Has metadata — build dirty update (increment seq)
            encryptedMeta = try v10Encrypt(
                buildUpdateMetadata(existingFields: fields, timestampMs: tsMs),
                key: aesKey
            )
        } else {
            // No metadata — create fresh (same as insert)
            let tagHash = computeClientTagHash(
                url: url, usernameElement: "", usernameValue: username,
                passwordElement: "", realm: realm
            )
            encryptedMeta = try v10Encrypt(
                buildNewMetadata(clientTagHash: tagHash, timestampMs: tsMs),
                key: aesKey
            )
        }

        // Open DB for writing
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK
        else {
            throw ChromeToolError.databaseError("Failed to open DB for update")
        }
        defer { sqlite3_close(db) }

        guard sqlite3_exec(db, "BEGIN", nil, nil, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to begin transaction")
        }

        let TR = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

        // UPDATE logins
        var loginStmt: OpaquePointer?
        let loginSQL = """
            UPDATE logins SET password_value=?, date_password_modified=? WHERE id=?
            """
        guard sqlite3_prepare_v2(db, loginSQL, -1, &loginStmt, nil) == SQLITE_OK
        else {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("Failed to prepare UPDATE logins")
        }

        encryptedPw.withUnsafeBytes { ptr in
            sqlite3_bind_blob(loginStmt, 1, ptr.baseAddress,
                              Int32(encryptedPw.count), TR)
        }
        sqlite3_bind_int64(loginStmt, 2, now)
        sqlite3_bind_int64(loginStmt, 3, loginID)

        guard sqlite3_step(loginStmt) == SQLITE_DONE else {
            let err = String(cString: sqlite3_errmsg(db))
            sqlite3_finalize(loginStmt)
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("UPDATE logins failed: \(err)")
        }
        sqlite3_finalize(loginStmt)

        // Metadata: UPDATE if existing, INSERT if new
        var metaStmt: OpaquePointer?
        let metaSQL: String
        if hasExistingMeta {
            metaSQL = """
                UPDATE sync_entities_metadata SET metadata=? WHERE storage_key=?
                """
        } else {
            metaSQL = """
                INSERT INTO sync_entities_metadata (metadata, storage_key) VALUES (?, ?)
                """
        }

        guard sqlite3_prepare_v2(db, metaSQL, -1, &metaStmt, nil) == SQLITE_OK
        else {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("Failed to prepare metadata write")
        }

        encryptedMeta.withUnsafeBytes { ptr in
            sqlite3_bind_blob(metaStmt, 1, ptr.baseAddress,
                              Int32(encryptedMeta.count), TR)
        }
        sqlite3_bind_int64(metaStmt, 2, loginID)

        guard sqlite3_step(metaStmt) == SQLITE_DONE else {
            let err = String(cString: sqlite3_errmsg(db))
            sqlite3_finalize(metaStmt)
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("Metadata write failed: \(err)")
        }
        sqlite3_finalize(metaStmt)

        guard sqlite3_exec(db, "COMMIT", nil, nil, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to commit update")
        }
    }

    // MARK: - Injection

    /// Inject one new credential + dirty sync metadata. Returns the new login ID.
    private func injectOne(dbPath: String, aesKey: Data,
                           url: String, username: String,
                           password: String, realm: String) throws -> Int64 {
        // Encrypt password
        let encryptedPw = try v10Encrypt(Data(password.utf8), key: aesKey)

        // Build dirty sync metadata
        let tagHash = computeClientTagHash(
            url: url, usernameElement: "", usernameValue: username,
            passwordElement: "", realm: realm
        )
        let tsMs = unixMs()
        let metaProto = buildNewMetadata(clientTagHash: tagHash, timestampMs: tsMs)
        let encryptedMeta = try v10Encrypt(metaProto, key: aesKey)

        let now = webkitTimestamp()

        // Open DB
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK
        else {
            throw ChromeToolError.databaseError("Failed to open DB for writing")
        }
        defer { sqlite3_close(db) }

        guard sqlite3_exec(db, "BEGIN", nil, nil, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to begin transaction")
        }

        // INSERT into logins
        let insertSQL = """
            INSERT INTO logins (
                origin_url, action_url, username_element, username_value,
                password_element, password_value, submit_element, signon_realm,
                date_created, blacklisted_by_user, scheme, password_type,
                times_used, form_data, display_name, icon_url, federation_url,
                skip_zero_click, generation_upload_status, possible_username_pairs,
                date_last_used, moving_blocked_for, date_password_modified,
                sender_email, sender_name, date_received,
                sharing_notification_displayed, keychain_identifier,
                sender_profile_image_url, date_last_filled, actor_login_approved
            ) VALUES (
                ?1, '', '', ?2, '', ?3, '', ?4,
                ?5, 0, 0, 3, 0, X'', '', '', '',
                0, 0, X'', 0, X'', ?6,
                '', '', 0, 0, X'', '', 0, 0
            )
            """

        var insertStmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, insertSQL, -1, &insertStmt, nil) == SQLITE_OK
        else {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            let err = String(cString: sqlite3_errmsg(db))
            throw ChromeToolError.databaseError("Failed to prepare INSERT: \(err)")
        }

        let TR = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(insertStmt, 1, url, -1, TR)
        sqlite3_bind_text(insertStmt, 2, username, -1, TR)
        encryptedPw.withUnsafeBytes { ptr in
            sqlite3_bind_blob(insertStmt, 3, ptr.baseAddress,
                              Int32(encryptedPw.count), TR)
        }
        sqlite3_bind_text(insertStmt, 4, realm, -1, TR)
        sqlite3_bind_int64(insertStmt, 5, now)
        sqlite3_bind_int64(insertStmt, 6, now)

        let insertStatus = sqlite3_step(insertStmt)
        sqlite3_finalize(insertStmt)

        if insertStatus == SQLITE_CONSTRAINT {
            // UNIQUE constraint fired — entry already exists but findExistingLoginID
            // didn't match (likely Chrome sync modified the URL format). Not an error.
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            return -1  // Caller treats -1 as "already existed"
        }

        guard insertStatus == SQLITE_DONE else {
            let err = String(cString: sqlite3_errmsg(db))
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("INSERT login failed: \(err)")
        }

        let newID = sqlite3_last_insert_rowid(db)

        // INSERT into sync_entities_metadata
        var metaStmt: OpaquePointer?
        let metaSQL = """
            INSERT INTO sync_entities_metadata (storage_key, metadata) VALUES (?, ?)
            """
        guard sqlite3_prepare_v2(db, metaSQL, -1, &metaStmt, nil) == SQLITE_OK else {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("Failed to prepare metadata INSERT")
        }

        sqlite3_bind_int64(metaStmt, 1, newID)
        encryptedMeta.withUnsafeBytes { ptr in
            sqlite3_bind_blob(metaStmt, 2, ptr.baseAddress,
                              Int32(encryptedMeta.count), TR)
        }

        guard sqlite3_step(metaStmt) == SQLITE_DONE else {
            let err = String(cString: sqlite3_errmsg(db))
            sqlite3_finalize(metaStmt)
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw ChromeToolError.databaseError("INSERT metadata failed: \(err)")
        }
        sqlite3_finalize(metaStmt)

        guard sqlite3_exec(db, "COMMIT", nil, nil, nil) == SQLITE_OK else {
            throw ChromeToolError.databaseError("Failed to commit")
        }

        return newID
    }

    // MARK: - Sync Verification

    /// Check how many of the given login row IDs have synced to Google.
    /// Copies the DB to a temp file first — Chrome holds a WAL lock while running.
    private func verifySynced(dbPath: String, aesKey: Data,
                              ids: [Int64]) throws -> Int {
        let fm = FileManager.default
        let tempPath = fm.temporaryDirectory
            .appendingPathComponent("goodboy_verify_\(UUID().uuidString).db")
            .path
        try fm.copyItem(atPath: dbPath, toPath: tempPath)
        defer { try? fm.removeItem(atPath: tempPath) }

        var db: OpaquePointer?
        guard sqlite3_open_v2(tempPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK
        else {
            throw ChromeToolError.databaseError(
                "Failed to open DB for verification"
            )
        }
        defer { sqlite3_close(db) }

        var synced = 0
        for id in ids {
            var stmt: OpaquePointer?
            let sql = "SELECT metadata FROM sync_entities_metadata WHERE storage_key=?"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK
            else { continue }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int64(stmt, 1, id)

            guard sqlite3_step(stmt) == SQLITE_ROW else { continue }

            let blobPtr = sqlite3_column_blob(stmt, 0)
            let blobLen = sqlite3_column_bytes(stmt, 0)
            guard let ptr = blobPtr, blobLen > 0 else { continue }

            let encrypted = Data(bytes: ptr, count: Int(blobLen))
            guard let decrypted = try? v10Decrypt(encrypted, key: aesKey)
            else { continue }

            let fields = decodeMetadata(decrypted)
            let hasServerID = fields[2] != nil
            let seq = (fields[4] as? Int64) ?? 0
            let acked = (fields[5] as? Int64) ?? 0
            let serverVer = (fields[6] as? Int64) ?? -1

            if hasServerID && seq == acked && serverVer > 0 {
                synced += 1
            }
        }

        Self.log.info("Verified: \(synced)/\(ids.count) synced")
        return synced
    }

    // MARK: - URL Helpers

    private func normalizeURL(_ url: String) -> String {
        var u = url
        if !u.hasPrefix("http://") && !u.hasPrefix("https://") {
            u = "https://" + u
        }
        if !u.hasSuffix("/") {
            u += "/"
        }
        return u
    }

    /// Chrome's HTML-form `signon_realm` must be origin-only
    /// (`scheme://host[:port]/`). `origin_url` and `action_url` carry the
    /// full page URL; `signon_realm` is the scope key the password
    /// manager filters by. Surfaced 2026-05-04: the writer was setting
    /// `signon_realm = origin_url` (path-bleed) so saved creds were
    /// invisible to the autofill picker on any other page sharing the
    /// host. Strips path/query/fragment, normalizes path to `/`.
    private func originRealm(_ url: String) -> String {
        guard var c = URLComponents(string: url) else { return url }
        c.path = "/"
        c.query = nil
        c.fragment = nil
        return c.string ?? url
    }

    // MARK: - Chrome Crypto (Write Path)

    /// AES-128-CBC encrypt with space IV, PKCS7 padding, v10 prefix.
    private func v10Encrypt(_ plaintext: Data, key: Data) throws -> Data {
        let iv = Data(repeating: 0x20, count: 16)
        let bufLen = plaintext.count + kCCBlockSizeAES128
        var out = Data(count: bufLen)
        var outLen: size_t = 0

        let status = out.withUnsafeMutableBytes { oBuf in
            plaintext.withUnsafeBytes { pBuf in
                key.withUnsafeBytes { kBuf in
                    iv.withUnsafeBytes { ivBuf in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            kBuf.baseAddress, key.count,
                            ivBuf.baseAddress,
                            pBuf.baseAddress, plaintext.count,
                            oBuf.baseAddress, bufLen,
                            &outLen
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw ChromeToolError.cryptoError("AES encrypt failed (\(status))")
        }
        return Data([0x76, 0x31, 0x30]) + out.prefix(outLen)
    }

    /// Decrypt v10-prefixed AES-128-CBC blob.
    private func v10Decrypt(_ data: Data, key: Data) throws -> Data {
        guard data.count > 3,
              data.prefix(3) == Data([0x76, 0x31, 0x30])
        else {
            throw ChromeToolError.cryptoError("Not a v10 blob")
        }

        let payload = Data(data.dropFirst(3))
        let iv = Data(repeating: 0x20, count: 16)
        let bufLen = payload.count + kCCBlockSizeAES128
        var out = Data(count: bufLen)
        var outLen: size_t = 0

        let status = out.withUnsafeMutableBytes { oBuf in
            payload.withUnsafeBytes { pBuf in
                key.withUnsafeBytes { kBuf in
                    iv.withUnsafeBytes { ivBuf in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            kBuf.baseAddress, key.count,
                            ivBuf.baseAddress,
                            pBuf.baseAddress, payload.count,
                            oBuf.baseAddress, bufLen,
                            &outLen
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw ChromeToolError.cryptoError("AES decrypt failed (\(status))")
        }
        return out.prefix(outLen)
    }

    // MARK: - Client Tag Hash

    /// SHA1(type_prefix + escaped_fields_joined_by_pipe), base64-encoded.
    private func computeClientTagHash(url: String, usernameElement: String,
                                      usernameValue: String,
                                      passwordElement: String,
                                      realm: String) -> String {
        let typePrefix = Data([0x8A, 0xB3, 0x16, 0x00])
        let tag = [url, usernameElement, usernameValue, passwordElement, realm]
            .map { escapePath($0) }
            .joined(separator: "|")

        let input = typePrefix + Data(tag.utf8)

        var digest = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = input.withUnsafeBytes { iBuf in
            digest.withUnsafeMutableBytes { dBuf in
                CC_SHA1(
                    iBuf.baseAddress,
                    CC_LONG(input.count),
                    dBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        return digest.base64EncodedString()
    }

    /// Chrome's EscapePath: percent-encode non-safe UTF-8 bytes.
    private func escapePath(_ s: String) -> String {
        let safe: Set<UInt8> = Set(Array(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!$&'()*+,;=@/"
                .utf8
        ))

        var result = ""
        for byte in Array(s.utf8) {
            if safe.contains(byte) {
                result.append(Character(UnicodeScalar(byte)))
            } else {
                result.append(String(format: "%%%02X", byte))
            }
        }
        return result
    }

    // MARK: - Timestamps

    /// Microseconds since 1601-01-01 (Chrome's WebKit format).
    private func webkitTimestamp() -> Int64 {
        Int64((Date().timeIntervalSince1970 + 11_644_473_600) * 1_000_000)
    }

    /// Milliseconds since Unix epoch (for sync metadata protobuf).
    private func unixMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    // MARK: - Protobuf Encoding

    private func encodeVarint(_ value: UInt64) -> Data {
        var v = value
        var result = Data()
        repeat {
            var byte = UInt8(v & 0x7F)
            v >>= 7
            if v > 0 { byte |= 0x80 }
            result.append(byte)
        } while v > 0
        return result
    }

    private func encodeFieldVarint(_ field: Int, _ value: Int64) -> Data {
        let tag = UInt64(field << 3)  // wire type 0
        return encodeVarint(tag) + encodeVarint(UInt64(bitPattern: value))
    }

    private func encodeFieldBytes(_ field: Int, _ value: Data) -> Data {
        let tag = UInt64(field << 3 | 2)  // wire type 2
        return encodeVarint(tag) + encodeVarint(UInt64(value.count)) + value
    }

    /// Build EntityMetadata protobuf for a NEW entry (dirty, no server_id).
    private func buildNewMetadata(clientTagHash: String,
                                  timestampMs: Int64) -> Data {
        var proto = Data()
        proto.append(encodeFieldBytes(1, Data(clientTagHash.utf8)))
        proto.append(encodeFieldVarint(4, 1))             // sequence_number = 1
        proto.append(encodeFieldVarint(6, -1))            // server_version = -1
        proto.append(encodeFieldVarint(7, timestampMs))   // creation_time
        proto.append(encodeFieldVarint(8, timestampMs))   // modification_time
        return proto
    }

    /// Build EntityMetadata protobuf for updating an existing synced entry.
    /// Increments sequence_number to mark dirty, preserves all server state.
    private func buildUpdateMetadata(existingFields: [Int: Any],
                                     timestampMs: Int64) -> Data {
        var proto = Data()

        // Field 1: client_tag_hash (keep)
        if let tagHash = existingFields[1] as? Data {
            proto.append(encodeFieldBytes(1, tagHash))
        }

        // Field 2: server_id (keep if present)
        if let serverId = existingFields[2] as? Data {
            proto.append(encodeFieldBytes(2, serverId))
        }

        // Field 4: sequence_number (increment by 1 — marks dirty)
        let seq = (existingFields[4] as? Int64) ?? 0
        proto.append(encodeFieldVarint(4, seq + 1))

        // Field 5: acked_sequence_number (keep if > 0)
        if let acked = existingFields[5] as? Int64, acked > 0 {
            proto.append(encodeFieldVarint(5, acked))
        }

        // Field 6: server_version (keep)
        if let serverVer = existingFields[6] as? Int64 {
            proto.append(encodeFieldVarint(6, serverVer))
        }

        // Field 7: creation_time (keep original)
        let creationTime = (existingFields[7] as? Int64) ?? timestampMs
        proto.append(encodeFieldVarint(7, creationTime))

        // Field 8: modification_time (now)
        proto.append(encodeFieldVarint(8, timestampMs))

        return proto
    }

    // MARK: - Protobuf Decoding (verification + update reads)

    private func decodeMetadata(_ data: Data) -> [Int: Any] {
        var fields: [Int: Any] = [:]
        var pos = 0
        let bytes = Array(data)

        while pos < bytes.count {
            let (tag, p1) = decodeRawVarint(bytes, pos)
            pos = p1
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x07)

            if wireType == 0 {
                let (val, p2) = decodeRawVarint(bytes, pos)
                pos = p2
                fields[fieldNum] = Int64(bitPattern: val)
            } else if wireType == 2 {
                let (len, p2) = decodeRawVarint(bytes, pos)
                pos = p2
                let end = pos + Int(len)
                if end <= bytes.count {
                    fields[fieldNum] = Data(bytes[pos..<end])
                }
                pos = end
            } else {
                break
            }
        }
        return fields
    }

    private func decodeRawVarint(_ bytes: [UInt8], _ start: Int) -> (UInt64, Int) {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var pos = start
        while pos < bytes.count {
            let byte = bytes[pos]
            result |= UInt64(byte & 0x7F) << shift
            pos += 1
            if byte & 0x80 == 0 { break }
            shift += 7
        }
        return (result, pos)
    }

    // MARK: - Public Write Surface

    /// Write SecuredBox credentials to a Chrome login database at `dbPath`.
    ///
    /// Stateless: the caller owns the database path (real profile DB for a
    /// direct write, or a cloned DB for out-of-band sync). Returns the row
    /// IDs that were touched so the caller can pass them to
    /// `verifyChromeSync` after Chrome has had a chance to sync.
    public static func performChromeWrite(
        dbPath: String, aesKey: Data, box: SecuredBox
    ) throws -> ChromeWriteResult {
        let tool = ChromeTool()
        let result = try tool.upsertAll(dbPath: dbPath, aesKey: aesKey, securedBox: box)
        return ChromeWriteResult(
            ids: result.ids,
            inserted: result.inserted,
            updated: result.updated,
            skippedDuplicates: result.skippedDuplicates,
            warnings: result.warnings
        )
    }

    /// Count how many of the given login row IDs have synced to Google.
    ///
    /// Decrypts each row's `sync_entities_metadata` protobuf and counts rows
    /// that have a server ID assigned, a matching sequence/ack, and a
    /// positive server version. Opens the DB read-only against a temp copy,
    /// so it's safe to call while Chrome holds a WAL lock on the source.
    public static func verifyChromeSync(
        dbPath: String, aesKey: Data, ids: [Int64]
    ) throws -> Int {
        let tool = ChromeTool()
        return try tool.verifySynced(dbPath: dbPath, aesKey: aesKey, ids: ids)
    }
}

// MARK: - Public Write Result

/// Outcome of a `ChromeTool.performChromeWrite` call.
public struct ChromeWriteResult: Sendable {
    public let ids: [Int64]
    public let inserted: Int
    public let updated: Int
    public let skippedDuplicates: Int
    public let warnings: [String]

    public var total: Int { inserted + updated + skippedDuplicates }
    public var writtenCount: Int { inserted + updated }

    /// e.g. "3 new, 1 updated" or "2 new, 1 already existed"
    public var breakdown: String {
        var parts: [String] = []
        if inserted > 0 { parts.append("\(inserted) new") }
        if updated > 0 { parts.append("\(updated) updated") }
        if skippedDuplicates > 0 { parts.append("\(skippedDuplicates) already existed") }
        return parts.joined(separator: ", ")
    }
}

// MARK: - Errors

public enum ChromeToolError: Error, LocalizedError {
    case notFound(String)
    case databaseError(String)
    case keychainError(String)
    case cryptoError(String)

    public var errorDescription: String? {
        switch self {
        case .notFound(let msg): return msg
        case .databaseError(let msg): return msg
        case .keychainError(let msg): return msg
        case .cryptoError(let msg): return msg
        }
    }
}
