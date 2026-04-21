// Wraps `bw` (Bitwarden CLI) subprocess calls for vault access.
// Session tokens via BW_SESSION env var. All secrets via stdin/env only.

import Foundation
import os.log
import FlowEngine

public final class BitwardenCLI: Sendable {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "BitwardenCLI")
    private static let appDataDir: URL = {
        let dir = AppPaths.base.appendingPathComponent("BitwardenCLI", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    private static func commandEnv(_ extra: [String: String] = [:]) -> [String: String] {
        var env = extra
        env["BITWARDENCLI_APPDATA_DIR"] = appDataDir.path
        return env
    }

    // MARK: - Binary location

    public static func findBinary() -> String? {
        CLIRunner.findBinary(
            envKey: "GOODBOY_BW_CLI_PATH",
            standardPaths: [
                "/opt/homebrew/bin/bw",   // arm64
                "/usr/local/bin/bw",      // x86
            ],
            whichName: "bw",
            expectedTeamIds: ["LTZ2PFU5D6"]   // Bitwarden Inc.
        )
    }

    public static var isAvailable: Bool {
        findBinary() != nil
    }

    // MARK: - Vault lifecycle

    // TTL cache — avoids spawning `bw status` on every reconcile.
    // Disk-backed: cold start loads from disk instead of blocking on CLI.
    private static let statusLock = NSLock()
    private nonisolated(unsafe) static var cachedStatus: BWStatus?
    private nonisolated(unsafe) static var statusCacheTime: ContinuousClock.Instant?
    private static let statusTTL: Duration = .seconds(30)
    private static let statusCachePath = AppPaths.base.appendingPathComponent("bw-status-cache.json")

    /// Check vault status. Returns parsed BWStatus. Cached for 30s.
    /// Cold start: returns disk cache instantly.
    public static func status() throws -> BWStatus {
        statusLock.lock()
        let cached = cachedStatus
        let cacheTime = statusCacheTime
        statusLock.unlock()

        if let cached, let cacheTime, ContinuousClock().now - cacheTime < statusTTL {
            return cached
        }

        // Cold start: seed from disk
        if cached == nil, let diskCached = loadStatusFromDisk() {
            statusLock.lock()
            cachedStatus = diskCached
            statusCacheTime = ContinuousClock().now
            statusLock.unlock()
            return diskCached
        }

        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }
        let result = try CLIRunner.runJSON(
            binary: binary,
            arguments: ["status", "--nointeraction"],
            environment: commandEnv(),
            as: BWStatus.self
        )

        statusLock.lock()
        cachedStatus = result
        statusCacheTime = ContinuousClock().now
        statusLock.unlock()
        saveStatusToDisk(result)

        return result
    }

    private static func loadStatusFromDisk() -> BWStatus? {
        guard let data = try? Data(contentsOf: statusCachePath) else { return nil }
        return try? JSONDecoder().decode(BWStatus.self, from: data)
    }

    private static func saveStatusToDisk(_ status: BWStatus) {
        guard let data = try? JSONEncoder().encode(status) else { return }
        try? data.write(to: statusCachePath, options: .atomic)
    }

    /// Invalidate cached status (call after login/unlock/logout).
    public static func invalidateStatusCache() {
        statusLock.lock()
        cachedStatus = nil
        statusCacheTime = nil
        statusLock.unlock()
        try? FileManager.default.removeItem(at: statusCachePath)
    }

    /// Wipe all bw CLI sidecar state for this device — the bw appdata
    /// directory (session tokens, vault snapshot) plus our status cache.
    /// Called from Reset Device. Safe to call when bw is not authenticated;
    /// the appdata dir is recreated lazily on next bw command.
    public static func clearSession() {
        invalidateStatusCache()
        try? FileManager.default.removeItem(at: appDataDir)
    }

    /// Set server URL (idempotent). Useful for EU/self-hosted vaults.
    /// Skips if already configured to the same URL (avoids "Logout required" trap).
    public static func configServer(url: String) throws {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        // Skip if already configured to the same URL.
        // bw config server on a logged-in vault says "Logout required" even for the same URL.
        if let current = try? status(), let currentUrl = current.serverUrl,
           currentUrl.trimmingCharacters(in: .init(charactersIn: "/")) == trimmed.trimmingCharacters(in: .init(charactersIn: "/")) {
            return
        }

        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["config", "server", trimmed, "--nointeraction"],
            environment: commandEnv(),
            timeout: 30
        )

        guard result.exitCode != 0 else { return }

        // If the CLI requires logout before switching servers, handle it automatically
        if result.stderr.lowercased().contains("logout") {
            try logout()
            let retry = try CLIRunner.run(
                binary: binary,
                arguments: ["config", "server", trimmed, "--nointeraction"],
                environment: commandEnv(),
                timeout: 30
            )
            guard retry.exitCode == 0 else {
                throw BitwardenError.configFailed(parseError(retry.stderr))
            }
            return
        }

        throw BitwardenError.configFailed(parseError(result.stderr))
    }

    /// Login with API key credentials.
    public static func loginAPIKey(clientId: String, clientSecret: String) throws {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }

        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["login", "--apikey", "--nointeraction"],
            environment: commandEnv([
                "BW_CLIENTID": clientId,
                "BW_CLIENTSECRET": clientSecret,
            ]),
            timeout: 60
        )

        guard result.exitCode == 0 else {
            let detail = parseError(result.stderr)
            if detail.lowercased().contains("already logged in") { return }
            throw BitwardenError.loginFailed(detail)
        }
    }

    /// Unlock the vault. Returns raw session token string.
    public static func unlock(password: String) throws -> String {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }

        // M11: feed the master password through stdin rather than env.
        // `bw unlock --passwordfile /dev/stdin` pulls the password from
        // stdin; it's still visible to ptrace-privileged debuggers on
        // the same user, but it's no longer exposed to anything that
        // can read the child's environ (other processes of the same
        // user via `ps -Ewwo`, crash reports, osqueryd, etc.).
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["unlock", "--passwordfile", "/dev/stdin", "--raw", "--nointeraction"],
            environment: commandEnv([:]),
            stdinString: password + "\n",
            timeout: 60
        )

        guard result.exitCode == 0 else {
            throw BitwardenError.unlockFailed(parseError(result.stderr))
        }

        let session = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !session.isEmpty else {
            throw BitwardenError.unlockFailed("No session token returned")
        }

        return session
    }

    /// Logout from vault. Idempotent — ignores "not logged in" errors.
    public static func logout() throws {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["logout", "--nointeraction"],
            environment: commandEnv(),
            timeout: 30
        )
        // "not logged in" is fine — that's the desired state
        if result.exitCode != 0 && !result.stderr.lowercased().contains("not logged in") {
            log.warning("bw logout returned non-zero: \(result.stderr)")
        }
    }

    /// Lock the vault.
    public static func lock() throws {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["lock", "--nointeraction"],
            environment: commandEnv(),
            timeout: 15
        )
        if result.exitCode != 0 {
            log.warning("bw lock returned non-zero: \(result.stderr)")
        }
    }

    /// Sync vault data from server.
    public static func sync(session: String) throws {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["sync", "--nointeraction"],
            environment: commandEnv(["BW_SESSION": session]),
            timeout: 60
        )
        if result.exitCode != 0 {
            throw BitwardenError.syncFailed(parseError(result.stderr))
        }
    }

    // MARK: - Data access

    /// List all items. Returns full items with secrets (unlike 1Password).
    public static func listItems(session: String) throws -> [BWItem] {
        guard let binary = findBinary() else {
            throw BitwardenError.cliNotFound
        }
        return try CLIRunner.runJSON(
            binary: binary,
            arguments: ["list", "items", "--nointeraction"],
            environment: commandEnv(["BW_SESSION": session]),
            as: [BWItem].self,
            timeout: 60
        )
    }

    private static func parseError(_ stderr: String) -> String {
        let lower = stderr.lowercased()

        // Crypto complaints during `bw unlock` that mean one thing to users:
        // the master password is wrong. Swallow the stack-trace noise.
        if lower.contains("bitwarden_crypto")
            || lower.contains("master_key")
            || lower.contains("decryption operation failed")
            || lower.contains("invalid master password") {
            return "The master password is incorrect."
        }

        if lower.contains("invalid_client") {
            return "Invalid API client for this server region. Set server URL correctly (EU: https://vault.bitwarden.eu)."
        }
        if lower.contains("unable to fetch serverconfig") {
            return "Unable to fetch server config. Check server URL and network."
        }
        if lower.contains("already logged in") || lower.contains("already authenticated") {
            return "Already logged in"
        }
        if lower.contains("not logged in") || lower.contains("unauthenticated") {
            return "Not logged in"
        }

        let firstUseful = stderr
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty && !$0.hasPrefix("at ") && !$0.hasPrefix("Node.js") && !$0.hasPrefix("^") }

        return firstUseful ?? stderr.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - Codable Models

public struct BWItem: Codable, Sendable {
    public let id: String
    public let type: Int              // 1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SSHKey
    public let name: String
    public let notes: String?
    public let favorite: Bool
    public let folderId: String?
    public let login: BWLogin?
    public let fields: [BWField]?
    public let revisionDate: String
    public let deletedDate: String?
}

public struct BWLogin: Codable, Sendable {
    public let username: String?
    public let password: String?
    public let totp: String?          // raw secret or otpauth:// URI
    public let uris: [BWURI]?
}

public struct BWURI: Codable, Sendable {
    public let uri: String?
    public let match: Int?            // 0=BaseDomain, 1=Host, 2=StartsWith, 3=RegExp, 4=Exact, 5=Never
}

public struct BWField: Codable, Sendable {
    public let type: Int              // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
    public let name: String?
    public let value: String?         // can be null
}

public struct BWStatus: Codable, Sendable {
    public let serverUrl: String?
    public let lastSync: String?
    public let userEmail: String?
    public let userId: String?
    public let status: String         // "locked" | "unlocked" | "unauthenticated"
}

// MARK: - Errors

public enum BitwardenError: Error, LocalizedError {
    case cliNotFound
    case configFailed(String)
    case loginFailed(String)
    case unlockFailed(String)
    case syncFailed(String)
    case listFailed(String)

    public var errorDescription: String? {
        switch self {
        case .cliNotFound:
            return "Bitwarden CLI not found. Install with `brew install bitwarden-cli` or set GOODBOY_BW_CLI_PATH."
        case .configFailed(let detail):
            return "Failed to configure Bitwarden server: \(detail)"
        case .loginFailed(let detail):
            return "Failed to log in with Bitwarden API key: \(detail)"
        case .unlockFailed(let detail):
            // `parseError` already humanizes the common crypto stack traces
            // into "The master password is incorrect." — don't double-wrap.
            return detail
        case .syncFailed(let detail):
            return "Bitwarden sync failed: \(detail). Check your internet connection."
        case .listFailed(let detail):
            return "Failed to list Bitwarden items: \(detail)"
        }
    }
}
