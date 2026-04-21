// Wraps `keepassxc-cli` subprocess calls for export, import, add, and db-info.
//
// Reference: Raycast keepass-loader.ts pattern + keepassxc-cli(1) man page.
// Password is always piped via stdin (never as command-line argument).

import Foundation
import os.log
import FlowEngine

public final class KeePassCLI: Sendable {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "KeePassCLI")

    // MARK: - Locate CLI binary

    /// Find the keepassxc-cli binary via CLIRunner.
    public static func findBinary() -> String? {
        CLIRunner.findBinary(
            envKey: "GOODBOY_KEEPASSXC_CLI_PATH",
            standardPaths: ["/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"],
            whichName: "keepassxc-cli",
            expectedTeamIds: ["G2S7P7J672"]   // Janek Bevendorff — KeePassXC maintainer
        )
    }

    /// Check if keepassxc-cli is available.
    public static var isAvailable: Bool {
        findBinary() != nil
    }

    // MARK: - Detect database

    /// KeePassXC cached config path (Qt writes runtime state here).
    private static let cachedIniPath = NSString(
        string: "~/Library/Caches/KeePassXC/keepassxc.ini"
    ).expandingTildeInPath

    /// Auto-detect the user's most recently active KeePassXC database.
    /// Reads `LastActiveDatabase` from KeePassXC's cached ini file.
    /// Returns the path if the file exists on disk, nil otherwise.
    public static func detectDatabase() -> String? {
        guard FileManager.default.fileExists(atPath: cachedIniPath) else {
            return nil
        }
        guard let contents = try? String(contentsOfFile: cachedIniPath, encoding: .utf8) else {
            return nil
        }

        // Parse ini: look for LastActiveDatabase= under [General]
        var inGeneral = false
        for line in contents.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") {
                inGeneral = trimmed == "[General]"
                continue
            }
            if inGeneral, trimmed.hasPrefix("LastActiveDatabase=") {
                let path = String(trimmed.dropFirst("LastActiveDatabase=".count))
                if !path.isEmpty, FileManager.default.fileExists(atPath: path) {
                    return path
                }
            }
        }
        return nil
    }

    /// Detect all recently opened KeePassXC databases.
    /// Reads `LastDatabases` and `LastActiveDatabase` from keepassxc.ini.
    /// Returns paths that exist on disk, sorted alphabetically.
    public static func detectAllDatabases() -> [String] {
        guard FileManager.default.fileExists(atPath: cachedIniPath) else { return [] }
        guard let contents = try? String(contentsOfFile: cachedIniPath, encoding: .utf8) else { return [] }

        var paths = Set<String>()
        var inGeneral = false

        for line in contents.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") {
                inGeneral = trimmed == "[General]"
                continue
            }
            if inGeneral {
                if trimmed.hasPrefix("LastActiveDatabase=") {
                    let path = String(trimmed.dropFirst("LastActiveDatabase=".count))
                    if !path.isEmpty { paths.insert(path) }
                } else if trimmed.hasPrefix("LastDatabases=") {
                    let value = String(trimmed.dropFirst("LastDatabases=".count))
                    for part in value.components(separatedBy: ", ") {
                        let path = part.trimmingCharacters(in: .whitespaces)
                        if !path.isEmpty { paths.insert(path) }
                    }
                }
            }
        }

        return paths.filter { FileManager.default.fileExists(atPath: $0) }.sorted()
    }

    // MARK: - Run CLI command (private)

    /// Execute a keepassxc-cli command with password on stdin.
    /// Delegates to CLIRunner for subprocess management.
    /// Returns (stdout, stderr, exitCode).
    private static func run(
        arguments: [String],
        stdinString: String? = nil,
        timeout: TimeInterval = 30
    ) throws -> (stdout: String, stderr: String, exitCode: Int32) {
        guard let binary = findBinary() else {
            throw KeePassError.cliNotFound
        }

        return try CLIRunner.run(
            binary: binary,
            arguments: arguments,
            stdinString: stdinString,
            timeout: timeout
        )
    }

    // MARK: - db-info

    /// Validate database credentials. Returns true if credentials are valid.
    public static func dbInfo(dbPath: String, password: String, keyFile: String? = nil) throws -> Bool {
        var args = ["db-info", "-q"]
        if let keyFile = keyFile {
            args.append(contentsOf: ["-k", keyFile])
        }
        args.append("--")
        args.append(dbPath)

        let result = try run(arguments: args, stdinString: password + "\n")

        if result.exitCode != 0 {
            log.error("db-info failed: \(result.stderr)")
            return false
        }
        return true
    }

    // MARK: - Export XML

    /// Export the entire database as KeePass XML.
    /// This is the only CLI method that includes custom string fields (KPEX passkey attributes).
    public static func exportXML(dbPath: String, password: String, keyFile: String? = nil) throws -> String {
        var args = ["export", "-f", "xml", "-q"]
        if let keyFile = keyFile {
            args.append(contentsOf: ["-k", keyFile])
        }
        args.append("--")
        args.append(dbPath)

        let result = try run(arguments: args, stdinString: password + "\n", timeout: 60)

        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("export failed: \(result.stderr)")
        }

        guard !result.stdout.isEmpty else {
            throw KeePassError.cliInvalidOutput("export returned empty output")
        }

        return result.stdout
    }

    // MARK: - Export CSV

    /// Export the database as CSV (simpler, but no custom attributes / passkeys).
    public static func exportCSV(dbPath: String, password: String, keyFile: String? = nil) throws -> String {
        var args = ["export", "-f", "csv", "-q"]
        if let keyFile = keyFile {
            args.append(contentsOf: ["-k", keyFile])
        }
        args.append("--")
        args.append(dbPath)

        let result = try run(arguments: args, stdinString: password + "\n", timeout: 60)

        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("export failed: \(result.stderr)")
        }

        return result.stdout
    }

    // MARK: - Add Entry

    /// Add a single entry to the database.
    /// `-p` (--password-prompt) tells keepassxc-cli to read the entry password from stdin.
    /// Stdin receives: line 1 = DB master password, line 2 = entry password.
    public static func addEntry(
        dbPath: String,
        password: String,
        title: String,
        url: String,
        username: String,
        entryPassword: String,
        group: String? = nil,
        keyFile: String? = nil
    ) throws {
        var args = ["add", "-q"]
        args.append(contentsOf: ["-u", username])
        args.append(contentsOf: ["--url", url])
        args.append("-p")
        if let keyFile = keyFile {
            args.append(contentsOf: ["-k", keyFile])
        }
        args.append("--")
        args.append(dbPath)

        // Entry path: keepassxc-cli uses "/" as group separator.
        // Root group entries need a leading "/" (e.g. "/mysite.com").
        let entryPath: String
        if let group = group, !group.isEmpty {
            entryPath = "/\(group)/\(title)"
        } else {
            entryPath = "/\(title)"
        }
        args.append(entryPath)

        // Pipe both passwords via stdin: DB password first, then entry password
        let stdinData = password + "\n" + entryPassword + "\n"
        let result = try run(arguments: args, stdinString: stdinData)

        if result.exitCode != 0 {
            let stderr = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)

            // Duplicate entry — compare existing password, update if different.
            if stderr.contains("Could not create entry") {
                let existing = try showEntry(dbPath: dbPath, password: password,
                                             entryPath: entryPath, attribute: "Password", keyFile: keyFile)
                if existing == entryPassword {
                    log.info("Entry '\(title, privacy: .private)' already exists with same password — skipped")
                    return
                }
                try editEntry(dbPath: dbPath, password: password, entryPath: entryPath,
                              username: username, url: url, entryPassword: entryPassword, keyFile: keyFile)
                log.info("Entry '\(title, privacy: .private)' updated (password changed)")
                return
            }

            throw KeePassError.cliExecFailed("add failed: \(stderr)")
        }

        log.info("Entry added: \(title, privacy: .private)")
    }

    // MARK: - Show Entry Attribute

    /// Read a single attribute from an existing entry. Returns the value trimmed.
    private static func showEntry(
        dbPath: String, password: String, entryPath: String,
        attribute: String, keyFile: String? = nil
    ) throws -> String {
        var args = ["show", "-q", "-s", "-a", attribute]
        if let keyFile = keyFile { args.append(contentsOf: ["-k", keyFile]) }
        args.append("--")
        args.append(dbPath)
        args.append(entryPath)

        let result = try run(arguments: args, stdinString: password + "\n")
        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("show failed: \(result.stderr)")
        }
        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Edit Entry

    /// Update an existing entry's username, URL, and password.
    private static func editEntry(
        dbPath: String, password: String, entryPath: String,
        username: String, url: String, entryPassword: String,
        keyFile: String? = nil
    ) throws {
        var args = ["edit", "-q", "-u", username, "--url", url, "-p"]
        if let keyFile = keyFile { args.append(contentsOf: ["-k", keyFile]) }
        args.append("--")
        args.append(dbPath)
        args.append(entryPath)

        let stdinData = password + "\n" + entryPassword + "\n"
        let result = try run(arguments: args, stdinString: stdinData)
        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("edit failed: \(result.stderr)")
        }
    }

    // MARK: - Import (from XML/CSV)

    /// Import entries from an XML or CSV file.
    public static func importFile(
        dbPath: String,
        password: String,
        importPath: String,
        keyFile: String? = nil
    ) throws {
        var args = ["import", "-q", "-p"]
        if let keyFile = keyFile {
            args.append(contentsOf: ["--set-key-file", keyFile])
        }
        // keepassxc-cli import: `import <xml> <database>` — XML first, new DB second.
        args.append(importPath)
        args.append("--")
        args.append(dbPath)

        // -p requires password + repeat on stdin
        let result = try run(arguments: args, stdinString: password + "\n" + password + "\n", timeout: 60)

        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("import failed: \(result.stderr)")
        }

        log.info("Import complete from \(importPath)")
    }

    // MARK: - Import XML String

    /// Write an XML string to a 0600 temp file, import it via
    /// `keepassxc-cli import`, then unlink. The file is created before
    /// any content is written (posixPermissions attribute on
    /// createFile), so the window where the XML touches disk is always
    /// 0600. A defer handles normal cleanup; a best-effort sweep at
    /// startup (sweepOrphanImportFiles) reclaims stragglers from a
    /// crash or SIGKILL. This is M3 — we considered a named-pipe path
    /// per the audit but keepassxc-cli's `import --xml` wants a
    /// regular file, so we tightened the tempfile path instead.
    public static func importXML(
        dbPath: String,
        password: String,
        xmlString: String,
        keyFile: String? = nil
    ) throws {
        let tmpDir = FileManager.default.temporaryDirectory
        let tmpFile = tmpDir.appendingPathComponent("goodboy-import-\(UUID().uuidString).xml")

        // Clean up any stale temp file from a previous run
        try? FileManager.default.removeItem(at: tmpFile)

        // Write with restrictive permissions (0600).
        FileManager.default.createFile(atPath: tmpFile.path, contents: nil, attributes: [
            .posixPermissions: 0o600
        ])
        try xmlString.write(to: tmpFile, atomically: false, encoding: .utf8)

        defer {
            try? FileManager.default.removeItem(at: tmpFile)
        }

        try importFile(dbPath: dbPath, password: password, importPath: tmpFile.path, keyFile: keyFile)
        log.info("XML import complete (temp file cleaned)")
    }

    /// Reap any `goodboy-import-*.xml` files left behind by a crashed
    /// or SIGKILL'd previous run. Cheap; called once at startup.
    public static func sweepOrphanImportFiles() {
        let tmpDir = FileManager.default.temporaryDirectory
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: tmpDir,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else { return }
        for url in entries {
            let name = url.lastPathComponent
            if name.hasPrefix("goodboy-import-") && name.hasSuffix(".xml") {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    // MARK: - Merge

    /// Merge a source database into a destination database.
    /// `keepassxc-cli merge <destPath> <sourcePath>` — merges sourcePath INTO destPath.
    /// All secrets via stdin only.
    public static func merge(
        sourcePath: String,
        destPath: String,
        password: String,
        keyFile: String? = nil
    ) throws {
        guard findBinary() != nil else {
            throw KeePassError.cliNotFound
        }

        var args = ["merge", "-q"]
        if let keyFile = keyFile {
            args.append(contentsOf: ["-k", keyFile])
        }
        args.append(destPath)
        args.append("--")
        args.append(sourcePath)

        // merge needs the password for both databases — pipe same password for both
        let result = try run(arguments: args, stdinString: password + "\n" + password + "\n", timeout: 60)

        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("merge failed: \(result.stderr)")
        }

        log.info("Merge complete: \(sourcePath) → \(destPath)")
    }

    // MARK: - db-create

    /// Create a new KDBX database. Always KDBX 4 with Argon2d.
    /// Password via stdin. Optional `-t` for decryption time target.
    public static func dbCreate(
        dbPath: String,
        password: String,
        decryptionTimeMs: Int? = nil
    ) throws {
        var args = ["db-create", "-q", "-p"]
        if let ms = decryptionTimeMs {
            args.append(contentsOf: ["-t", String(ms)])
        }
        args.append("--")
        args.append(dbPath)

        let result = try run(arguments: args, stdinString: password + "\n" + password + "\n")

        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("db-create failed: \(result.stderr)")
        }

        log.info("Database created at \(dbPath)")
    }

    // MARK: - mkdir

    /// Create a group in the database. Parent groups must exist (create top-down).
    /// Password via stdin.
    public static func mkdir(
        dbPath: String,
        password: String,
        group: String,
        keyFile: String? = nil
    ) throws {
        var args = ["mkdir", "-q"]
        if let keyFile = keyFile {
            args.append(contentsOf: ["-k", keyFile])
        }
        args.append("--")
        args.append(dbPath)
        args.append(group)

        let result = try run(arguments: args, stdinString: password + "\n")

        if result.exitCode != 0 {
            throw KeePassError.cliExecFailed("mkdir failed: \(result.stderr)")
        }

        log.info("Group created: \(group, privacy: .private)")
    }
}
