// Shared Chrome primitives for all Chrome tools.
// Stateless enum — no singleton, no shared state.
//
// Owns: profile discovery, sync mode detection, Keychain-cached encryption key.
// Does NOT own: SQLite read/write, v10 encryption/decryption.

import Foundation
import CommonCrypto
import SQLite3
import os.log
import FlowEngine

// MARK: - Types

public struct ChromeProfileInfo {
    public let folder: String       // "Default", "Profile 2"
    public let name: String         // profile display name
    public let email: String?       // signed-in email, when available
    public let gaiaId: String?      // GAIA ID if signed in
}

public enum ChromeSyncMode: String {
    case accountStorage     // Login Data For Account has rows — safe for writes
    case chromeSync         // Login Data has rows — refuse for dest tools
    case both               // Both tables have rows — post-migration state, target LDFA (active table)
    case empty              // Neither table has rows — fresh profile
}

/// Row counts for both password tables in a Chrome profile.
public struct ProfileDBStats {
    public let loginDataLogins: Int
    public let loginDataMetadata: Int
    public let ldfaLogins: Int
    public let ldfaMetadata: Int
}

// MARK: - Chromium Browser Descriptor

public struct ChromiumBrowser: Sendable {
    public let name: String             // "Brave"
    public let slug: String             // "brave"
    public let dataDir: String          // "BraveSoftware/Brave-Browser" (relative to ~/Library/Application Support)
    public let keychainService: String  // "Brave Safe Storage"
    public let keychainAccount: String  // "Brave"
}

// MARK: - ChromeHelper

public enum ChromeHelper {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "ChromeHelper")

    /// Known Chromium-based browsers (excluding Chrome itself).
    /// Used by Chrome tools for slugPool and suggestDeviceConfigs().
    public static let knownChromiumBrowsers: [ChromiumBrowser] = [
        ChromiumBrowser(name: "Brave",   slug: "brave",   dataDir: "BraveSoftware/Brave-Browser",
                        keychainService: "Brave Safe Storage",   keychainAccount: "Brave"),
        ChromiumBrowser(name: "Edge",    slug: "edge",    dataDir: "Microsoft Edge",
                        keychainService: "Microsoft Edge Safe Storage", keychainAccount: "Microsoft Edge"),
        ChromiumBrowser(name: "Arc",     slug: "arc",     dataDir: "Arc/User Data",
                        keychainService: "Arc Safe Storage",     keychainAccount: "Arc"),
        ChromiumBrowser(name: "Vivaldi", slug: "vivaldi", dataDir: "Vivaldi",
                        keychainService: "Vivaldi Safe Storage", keychainAccount: "Vivaldi"),
        ChromiumBrowser(name: "Opera",   slug: "opera",   dataDir: "com.operasoftware.Opera",
                        keychainService: "Opera Safe Storage",   keychainAccount: "Opera"),
    ]

    public static let defaultChromeDir: String = {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Google/Chrome")
            .path
    }()

    public static let chromeBin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

    // MARK: - State Checks

    public static func isChromeInstalled() -> Bool {
        FileManager.default.fileExists(atPath: chromeBin)
    }

    public static func isChromeRunning() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", "Google Chrome"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    public static func profileExists(_ folder: String, chromeDir: String = defaultChromeDir) -> Bool {
        FileManager.default.fileExists(atPath: "\(chromeDir)/\(folder)/Login Data")
    }

    /// Gracefully quit Chrome via AppleScript and wait for exit (up to 10s).
    public static func quitChrome() async -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "tell application \"Google Chrome\" to quit"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try? process.run()
        process.waitUntilExit()

        for _ in 0..<20 {
            if !isChromeRunning() { return true }
            try? await Task.sleep(for: .milliseconds(500))
        }
        return !isChromeRunning()
    }

    /// Launch Chrome normally.
    public static func launchChrome() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = ["-a", "Google Chrome"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try? process.run()
    }

    // MARK: - Profile Discovery

    /// List all Chrome profiles from Local State → profile.info_cache.
    public static func listProfiles(chromeDir: String = defaultChromeDir) throws -> [ChromeProfileInfo] {
        let localStatePath = "\(chromeDir)/Local State"
        let data = try Data(contentsOf: URL(fileURLWithPath: localStatePath))
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profile = json["profile"] as? [String: Any],
              let infoCache = profile["info_cache"] as? [String: [String: Any]] else {
            throw ChromeHelperError.parseError("Cannot parse profile.info_cache from Local State")
        }

        return infoCache.map { folder, info in
            ChromeProfileInfo(
                folder: folder,
                name: info["name"] as? String ?? folder,
                email: info["user_name"] as? String,
                gaiaId: info["gaia_id"] as? String
            )
        }.sorted { $0.folder < $1.folder }
    }

    /// Resolve a profile by email, name, or folder name. Case-insensitive.
    public static func resolveProfile(query: String, chromeDir: String = defaultChromeDir) throws -> ChromeProfileInfo? {
        let profiles = try listProfiles(chromeDir: chromeDir)
        let q = query.lowercased()

        // Exact email match first
        if let match = profiles.first(where: { $0.email?.lowercased() == q }) {
            return match
        }
        // Exact folder match
        if let match = profiles.first(where: { $0.folder.lowercased() == q }) {
            return match
        }
        // Name contains
        if let match = profiles.first(where: { $0.name.lowercased().contains(q) }) {
            return match
        }
        // Email contains
        if let match = profiles.first(where: { $0.email?.lowercased().contains(q) == true }) {
            return match
        }

        return nil
    }

    // MARK: - Sync Mode Detection

    /// Detect sync mode using two signals:
    /// 1. **DB rows** — which table has data (definitive when non-empty)
    /// 2. **Preferences** — `google.services.consented_to_sync` (works even when tables are empty)
    ///
    /// DB rows take priority (they reflect reality). Preferences is the fallback
    /// for empty profiles where both tables have 0 rows.
    public static func detectSyncMode(folder: String, chromeDir: String = defaultChromeDir) -> ChromeSyncMode {
        let profileDir = "\(chromeDir)/\(folder)"
        let loginDataRows = rowCount(dbPath: "\(profileDir)/Login Data")
        let accountRows = rowCount(dbPath: "\(profileDir)/Login Data For Account")

        // If tables have data, that's definitive
        switch (loginDataRows > 0, accountRows > 0) {
        case (true, true):   return .both
        case (true, false):  return .chromeSync
        case (false, true):  return .accountStorage
        case (false, false): break  // Fall through to Preferences check
        }

        // Both tables empty — check Preferences for sync consent
        return detectSyncModeFromPreferences(profileDir: profileDir)
    }

    /// Detect sync mode from Preferences when both DB tables are empty.
    ///
    /// Two signals:
    /// - `consented_to_sync == true` → Chrome Sync (user turned on "sync everything")
    /// - Signed in (gaia_id in info_cache) but no sync consent → Account Storage
    /// - Not signed in → empty
    private static func detectSyncModeFromPreferences(profileDir: String) -> ChromeSyncMode {
        let prefsPath = "\(profileDir)/Preferences"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: prefsPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .empty
        }

        let google = json["google"] as? [String: Any]
        let services = google?["services"] as? [String: Any]
        let consentedToSync = services?["consented_to_sync"] as? Bool

        if consentedToSync == true {
            return .chromeSync
        }

        // Check if signed in via info_cache (gaia_id is set only for Google-linked profiles).
        // We derive the profile folder from the path to look it up.
        let folder = (profileDir as NSString).lastPathComponent
        let chromeDir = (profileDir as NSString).deletingLastPathComponent
        if let profiles = try? listProfiles(chromeDir: chromeDir),
           let profile = profiles.first(where: { $0.folder == folder }),
           let gaia = profile.gaiaId, !gaia.isEmpty {
            return .accountStorage
        }

        return .empty
    }

    /// Check which table has data and return its filename, or nil if empty.
    public static func detectActiveTable(folder: String, chromeDir: String = defaultChromeDir) -> String? {
        let profileDir = "\(chromeDir)/\(folder)"
        // Prefer Account Storage
        if rowCount(dbPath: "\(profileDir)/Login Data For Account") > 0 {
            return "Login Data For Account"
        }
        if rowCount(dbPath: "\(profileDir)/Login Data") > 0 {
            return "Login Data"
        }
        return nil
    }

    /// Row counts for both password tables — logins and sync metadata.
    /// Copies each DB to temp to avoid Chrome's WAL lock (works while Chrome is running).
    public static func profileStats(folder: String, chromeDir: String = defaultChromeDir) -> ProfileDBStats {
        let profileDir = "\(chromeDir)/\(folder)"
        let ldLogins = rowCount(dbPath: "\(profileDir)/Login Data", table: "logins")
        let ldMeta = rowCount(dbPath: "\(profileDir)/Login Data", table: "sync_entities_metadata")
        let ldfaLogins = rowCount(dbPath: "\(profileDir)/Login Data For Account", table: "logins")
        let ldfaMeta = rowCount(dbPath: "\(profileDir)/Login Data For Account", table: "sync_entities_metadata")
        return ProfileDBStats(
            loginDataLogins: ldLogins,
            loginDataMetadata: ldMeta,
            ldfaLogins: ldfaLogins,
            ldfaMetadata: ldfaMeta
        )
    }

    // MARK: - Browser Encryption Key

    /// Resolve the macOS Keychain service/account for a browser from its data directory.
    /// Falls back to Chrome if the directory doesn't match any known browser.
    public static func browserKeychainInfo(chromeDir: String) -> (service: String, account: String) {
        if let browser = knownChromiumBrowsers.first(where: { chromeDir.contains($0.dataDir) }) {
            return (browser.keychainService, browser.keychainAccount)
        }
        return ("Chrome Safe Storage", "Chrome")
    }

    /// Extract the browser's Safe Storage key from macOS Keychain, derive AES key,
    /// return as base64 string. This is the value stored in Keychain.devices per-device.
    /// Delegates to Keychain.readSystemKeychain — may trigger a macOS authorization dialog.
    public static func extractBrowserKey(chromeDir: String = defaultChromeDir) throws -> String {
        let info = browserKeychainInfo(chromeDir: chromeDir)
        let rawKey = try extractRawKey(service: info.service, account: info.account)
        let derived = deriveChromeKey(from: rawKey)
        return derived.base64EncodedString()
    }

    // MARK: - Private Helpers

    /// Extract a raw password from macOS login keychain via Keychain.readSystemKeychain.
    private static func extractRawKey(service: String, account: String) throws -> Data {
        let password = try Keychain.readSystemKeychain(service: service, account: account)
        guard let data = password.data(using: .utf8), !data.isEmpty else {
            throw ChromeHelperError.keychainError("'\(service)' key is empty.")
        }
        return data
    }

    /// Derive the AES key from Chrome's raw Keychain password.
    /// Chrome uses PBKDF2 with salt "saltysalt", 1003 iterations, 16-byte output.
    private static func deriveChromeKey(from rawKey: Data) -> Data {
        let salt = "saltysalt".data(using: .utf8)!
        var derivedKey = Data(count: 16)

        _ = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            rawKey.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        rawKey.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                        1003,
                        derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        16
                    )
                }
            }
        }

        return derivedKey
    }

    // MARK: - Watched Files (Fingerprinting)

    /// Paths to Chrome DB files whose mtime signals data changes.
    /// Resolves the profile param to a folder path.
    public static func watchedFiles(params: [String: String]) -> [String] {
        guard let profileQuery = params["profile"], !profileQuery.isEmpty else { return [] }
        let chromeDir = params["chromeDir"] ?? defaultChromeDir
        let folder = (try? resolveProfile(query: profileQuery, chromeDir: chromeDir))?.folder ?? profileQuery
        let profileDir = "\(chromeDir)/\(folder)"
        return [
            "\(profileDir)/Login Data",
            "\(profileDir)/Login Data For Account",
        ].filter { FileManager.default.fileExists(atPath: $0) }
    }

    // MARK: - Private Helpers

    /// Count rows in a table of a Chrome password DB.
    /// Copies to temp first to avoid Chrome's WAL lock.
    private static func rowCount(dbPath: String, table: String = "logins") -> Int {
        guard FileManager.default.fileExists(atPath: dbPath) else { return 0 }
        // Copy to temp to avoid Chrome's DB lock
        let tempPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("chrome_check_\(UUID().uuidString).db").path
        do {
            try FileManager.default.copyItem(atPath: dbPath, toPath: tempPath)
            defer { try? FileManager.default.removeItem(atPath: tempPath) }

            var db: OpaquePointer?
            guard sqlite3_open_v2(tempPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { return 0 }
            defer { sqlite3_close(db) }

            var stmt: OpaquePointer?
            let sql = "SELECT COUNT(*) FROM \(table)"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
            defer { sqlite3_finalize(stmt) }

            return sqlite3_step(stmt) == SQLITE_ROW ? Int(sqlite3_column_int(stmt, 0)) : 0
        } catch {
            return 0
        }
    }
}

// MARK: - Errors

public enum ChromeHelperError: Error, LocalizedError {
    case notInstalled(String)
    case parseError(String)
    case keychainError(String)
    case syncModeUnsafe(String)
    case profileNotFound(String)
    public var errorDescription: String? {
        switch self {
        case .notInstalled(let msg): return msg
        case .parseError(let msg): return msg
        case .keychainError(let msg): return msg
        case .syncModeUnsafe(let msg): return msg
        case .profileNotFound(let msg): return msg
        }
    }
}
