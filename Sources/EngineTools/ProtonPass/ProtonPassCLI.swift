// Wraps `pass-cli` (Proton Pass CLI) subprocess calls for vault access.
// Auth via env vars: PROTON_PASS_PASSWORD, PROTON_PASS_TOTP, PROTON_PASS_EXTRA_PASSWORD.
// Current pass-cli returns wrapped JSON and usually includes login secrets in item list.
// item view remains available as a fallback path.

import Foundation
import os.log
import FlowEngine

public final class ProtonPassCLI: Sendable {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "ProtonPassCLI")

    // MARK: - Binary location

    public static func findBinary() -> String? {
        CLIRunner.findBinary(
            envKey: "GOODBOY_PASSCLI_PATH",
            standardPaths: [
                "/opt/homebrew/bin/pass-cli",   // arm64
                "/usr/local/bin/pass-cli",      // x86
            ],
            whichName: "pass-cli"
        )
    }

    public static var isAvailable: Bool {
        findBinary() != nil
    }

    public enum AuthStatus: Sendable {
        case authenticated(email: String?)
        case unauthenticated
        case unknown(String)
    }

    // MARK: - Auth

    /// Login interactively. Password and optional TOTP/extra password via env vars.
    public static func loginInteractive(
        username: String,
        password: String,
        totp: String? = nil,
        extraPassword: String? = nil,
        timeout: TimeInterval = 60
    ) throws {
        guard let binary = findBinary() else {
            throw ProtonPassError.cliNotFound
        }

        var env: [String: String] = [
            "PROTON_PASS_PASSWORD": password,
        ]
        if let totp = totp, !totp.isEmpty {
            env["PROTON_PASS_TOTP"] = totp
        }
        if let extra = extraPassword, !extra.isEmpty {
            env["PROTON_PASS_EXTRA_PASSWORD"] = extra
        }

        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["login", "--interactive", username],
            environment: env,
            timeout: timeout
        )

        if result.exitCode != 0 {
            let stderr = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            let stdout = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            // "already logged in" is not an error
            if stderr.lowercased().contains("already logged in") || stderr.lowercased().contains("already authenticated") {
                return
            }

            // pass-cli can return a non-zero login result while still establishing
            // a valid authenticated session. Verify auth state before failing.
            if case .authenticated = authStatus() {
                return
            }

            let combined = [stderr, stdout]
                .filter { !$0.isEmpty }
                .joined(separator: "\n")
            throw ProtonPassError.loginFailed(parseLoginError(combined.isEmpty ? stderr : combined))
        }
    }

    // MARK: - Data access

    /// List items. Optional vault filter.
    public static func listItems(vault: String? = nil) throws -> [PPItem] {
        guard let binary = findBinary() else {
            throw ProtonPassError.cliNotFound
        }
        let requestedVault = vault?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !requestedVault.isEmpty {
            return try listItems(binary: binary, vaultName: requestedVault, shareId: nil)
        }

        // First try default behavior (uses default vault if configured).
        do {
            return try listItems(binary: binary, vaultName: nil, shareId: nil)
        } catch {
            // Some Proton accounts require explicit vault selection.
            guard isVaultSelectionRequiredError(error) else { throw error }

            let vaults = try listVaults()
            guard !vaults.isEmpty else {
                throw ProtonPassError.listFailed("No Proton vaults found. Create a vault or set a default vault in pass-cli settings.")
            }

            var all: [PPItem] = []
            for vaultInfo in vaults {
                if let shareId = vaultInfo.shareId, !shareId.isEmpty {
                    do {
                        let items = try listItems(binary: binary, vaultName: nil, shareId: shareId)
                        all.append(contentsOf: items)
                    } catch {
                        Self.log.warning("Skipping vault shareId=\(shareId, privacy: .private(mask: .hash)) due to list failure: \(error.localizedDescription)")
                    }
                    continue
                }

                if let name = vaultInfo.name, !name.isEmpty {
                    do {
                        let items = try listItems(binary: binary, vaultName: name, shareId: nil)
                        all.append(contentsOf: items)
                    } catch {
                        Self.log.warning("Skipping vault name=\(name, privacy: .private(mask: .hash)) due to list failure: \(error.localizedDescription)")
                    }
                }
            }

            if all.isEmpty {
                throw ProtonPassError.listFailed("Could not read items from any vault. Set a specific vault in device settings and retry.")
            }

            return all
        }
    }

    /// View a single item with secrets.
    public static func viewItem(shareId: String, itemId: String) throws -> PPItem {
        guard let binary = findBinary() else {
            throw ProtonPassError.cliNotFound
        }
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["item", "view", "pass://\(shareId)/\(itemId)", "--output", "json"],
            timeout: 30
        )
        guard result.exitCode == 0 else {
            throw ProtonPassError.viewFailed(normalizeCLIError(result.stderr))
        }
        return try parseViewItemOutput(result.stdout)
    }

    /// List available vaults.
    public static func listVaults() throws -> [PPVaultInfo] {
        guard let binary = findBinary() else {
            throw ProtonPassError.cliNotFound
        }
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["vault", "list", "--output", "json"],
            timeout: 30
        )
        guard result.exitCode == 0 else {
            throw ProtonPassError.listFailed(normalizeCLIError(result.stderr))
        }
        return try parseVaultListOutput(result.stdout)
    }

    /// Lightweight auth check.
    /// - authenticated: current CLI session can access Proton.
    /// - unauthenticated: known logged-out/session-invalid state.
    /// - unknown: unexpected stderr or parse issue.
    // TTL cache — avoids spawning `pass-cli info` on every reconcile.
    // Disk-backed: survives process restarts (MCP is short-lived).
    // On cold start: return disk cache, refresh in background.
    private static let authLock = NSLock()
    private nonisolated(unsafe) static var cachedAuthStatus: AuthStatus?
    private nonisolated(unsafe) static var authCacheTime: ContinuousClock.Instant?
    private static let authTTL: Duration = .seconds(30)
    private static let authCachePath = AppPaths.base.appendingPathComponent("pp-auth-cache.json")

    // Simple disk format for AuthStatus
    private struct DiskAuthStatus: Codable {
        let state: String  // "authenticated" | "unauthenticated" | "unknown"
        let detail: String?
    }

    public static func authStatus() -> AuthStatus {
        authLock.lock()
        let cached = cachedAuthStatus
        let cacheTime = authCacheTime
        authLock.unlock()

        if let cached, let cacheTime, ContinuousClock().now - cacheTime < authTTL {
            return cached
        }

        // Cold start: seed from disk
        if cached == nil, let diskCached = loadAuthFromDisk() {
            authLock.lock()
            cachedAuthStatus = diskCached
            authCacheTime = ContinuousClock().now
            authLock.unlock()
            return diskCached
        }

        let status = fetchAuth()

        authLock.lock()
        cachedAuthStatus = status
        authCacheTime = ContinuousClock().now
        authLock.unlock()
        saveAuthToDisk(status)

        return status
    }

    /// Fetch auth status from CLI (blocking).
    private static func fetchAuth() -> AuthStatus {
        guard let binary = findBinary() else {
            return .unknown("CLI not found")
        }

        do {
            let result = try CLIRunner.run(
                binary: binary,
                arguments: ["info", "--output", "json"],
                timeout: 20
            )

            if result.exitCode == 0 {
                let email = extractEmail(fromInfoJSON: result.stdout)
                return .authenticated(email: email)
            } else {
                let combined = [result.stderr, result.stdout]
                    .joined(separator: "\n")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                let lower = combined.lowercased()
                if lower.contains("requires an authenticated client")
                    || lower.contains("not logged in")
                    || lower.contains("session is some but is not logged in") {
                    return .unauthenticated
                } else {
                    return .unknown(combined.isEmpty ? "Unknown auth status error" : combined)
                }
            }
        } catch {
            return .unknown(error.localizedDescription)
        }
    }

    private static func loadAuthFromDisk() -> AuthStatus? {
        guard let data = try? Data(contentsOf: authCachePath),
              let disk = try? JSONDecoder().decode(DiskAuthStatus.self, from: data) else { return nil }
        switch disk.state {
        case "authenticated": return .authenticated(email: disk.detail)
        case "unauthenticated": return .unauthenticated
        default: return .unknown(disk.detail ?? "")
        }
    }

    private static func saveAuthToDisk(_ status: AuthStatus) {
        let disk: DiskAuthStatus
        switch status {
        case .authenticated(let email): disk = DiskAuthStatus(state: "authenticated", detail: email)
        case .unauthenticated: disk = DiskAuthStatus(state: "unauthenticated", detail: nil)
        case .unknown(let msg): disk = DiskAuthStatus(state: "unknown", detail: msg)
        }
        guard let data = try? JSONEncoder().encode(disk) else { return }
        try? data.write(to: authCachePath, options: .atomic)
    }

    /// Invalidate cached auth status (call after login/logout).
    /// Wipes both in-memory and disk caches — `authStatus()` falls back to
    /// the disk cache when the in-memory one is nil, so leaving the disk
    /// cache in place would let a stale "unauthenticated" status survive a
    /// successful login and surface as a spurious "Login completed but
    /// session is not authenticated" error from `connect()`.
    public static func invalidateAuthCache() {
        authLock.lock()
        cachedAuthStatus = nil
        authCacheTime = nil
        authLock.unlock()
        try? FileManager.default.removeItem(at: authCachePath)
    }

    private static func extractEmail(fromInfoJSON raw: String) -> String? {
        guard let data = raw.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) else {
            return nil
        }
        return findEmail(in: json)
    }

    private static func findEmail(in value: Any) -> String? {
        if let dict = value as? [String: Any] {
            for key in ["email", "userEmail", "accountEmail", "username"] {
                if let email = dict[key] as? String, email.contains("@") {
                    return email
                }
            }
            for nested in dict.values {
                if let email = findEmail(in: nested) { return email }
            }
        } else if let arr = value as? [Any] {
            for nested in arr {
                if let email = findEmail(in: nested) { return email }
            }
        }
        return nil
    }

    private static func parseLoginError(_ stderr: String) -> String {
        let normalized = normalizeCLIError(stderr)
        let lower = normalized.lowercased()
        if lower.contains("not yet allowed to use our cli") {
            return "Your Proton account is not yet enabled for Proton Pass CLI. Open Proton email for the enablement message or check Proton Pass CLI eligibility."
        }
        if lower.contains("422 unprocessable entity") {
            return "Proton rejected the login request (422). Verify email/password and use a fresh one-time 2FA code only when prompted."
        }
        if lower.contains("interactive login flow") {
            return "Proton Pass interactive login failed. Check credentials, network access, and try again."
        }
        return normalized
    }

    private static func normalizeCLIError(_ raw: String) -> String {
        let noANSI = raw.replacingOccurrences(
            of: #"\x1B\[[0-9;]*[A-Za-z]"#,
            with: "",
            options: .regularExpression
        )
        let trimmed = noANSI.trimmingCharacters(in: .whitespacesAndNewlines)
        let noErrorPrefix = trimmed.replacingOccurrences(
            of: #"(?i)^error:\s*"#,
            with: "",
            options: .regularExpression
        )
        return noErrorPrefix.replacingOccurrences(
            of: #"(?i)^proton pass login failed:\s*"#,
            with: "",
            options: .regularExpression
        )
    }

    private static func listItems(
        binary: String,
        vaultName: String?,
        shareId: String?
    ) throws -> [PPItem] {
        var args = ["item", "list", "--output", "json"]
        if let shareId, !shareId.isEmpty {
            args += ["--share-id", shareId]
        } else if let vaultName, !vaultName.isEmpty {
            // `--` sentinel stops pass-cli from parsing a crafted vault name
            // like "--format yaml" as an additional flag. Matches the
            // argv-hardening invariant KeePassCLI applies on every call.
            args.append("--")
            args.append(vaultName)
        }

        let result = try CLIRunner.run(
            binary: binary,
            arguments: args,
            timeout: 60
        )
        guard result.exitCode == 0 else {
            throw ProtonPassError.listFailed(normalizeCLIError(result.stderr))
        }
        return try parseItemListOutput(result.stdout)
    }

    private static func isVaultSelectionRequiredError(_ error: Error) -> Bool {
        let message = error.localizedDescription.lowercased()
        return message.contains("provide either --share-id")
            || message.contains("--vault-name")
            || message.contains("set a default vault")
    }

    // MARK: - JSON Parsing (supports current + legacy pass-cli schemas)

    private static func parseVaultListOutput(_ raw: String) throws -> [PPVaultInfo] {
        let data = Data(raw.utf8)
        let decoder = JSONDecoder()

        if let wrapped = try? decoder.decode(PPVaultListResponse.self, from: data) {
            return wrapped.vaults
        }
        if let direct = try? decoder.decode([PPVaultInfo].self, from: data) {
            return direct
        }
        throw CLIRunnerError.jsonDecodeFailed("Unsupported Proton vault list JSON format")
    }

    private static func parseItemListOutput(_ raw: String) throws -> [PPItem] {
        let data = Data(raw.utf8)
        let decoder = JSONDecoder()

        if let wrapped = try? decoder.decode(PPItemListResponse.self, from: data) {
            return wrapped.items.map { mapNewItemToLegacy($0) }
        }
        if let direct = try? decoder.decode([PPItem].self, from: data) {
            return direct
        }
        throw CLIRunnerError.jsonDecodeFailed("Unsupported Proton item list JSON format")
    }

    private static func parseViewItemOutput(_ raw: String) throws -> PPItem {
        let data = Data(raw.utf8)
        let decoder = JSONDecoder()

        if let wrapped = try? decoder.decode(PPItemViewResponse.self, from: data) {
            return mapNewItemToLegacy(wrapped.item)
        }
        if let direct = try? decoder.decode(PPItem.self, from: data) {
            return direct
        }
        throw CLIRunnerError.jsonDecodeFailed("Unsupported Proton item view JSON format")
    }

    private static func mapNewItemToLegacy(_ item: PPNewItem) -> PPItem {
        let login = item.content.content.login

        let metadata = PPMetadata(
            name: item.content.title,
            note: item.content.note
        )
        let content = PPContent(
            itemUsername: login?.username,
            itemEmail: login?.email,
            password: login?.password,
            urls: login?.urls,
            totpUri: login?.totpUri,
            passkeys: []
        )
        let type = (login == nil) ? "note" : "login"

        let extraFields: [PPExtraField]? = item.content.extraFields?.compactMap { field in
            let first = field.content.first
            let key = first?.key.lowercased() ?? "text"
            let value = first?.value
            let normalizedType: String
            if key.contains("totp") {
                normalizedType = "totp"
            } else if key.contains("hidden") {
                normalizedType = "hidden"
            } else {
                normalizedType = "text"
            }
            return PPExtraField(
                fieldName: field.name,
                type: normalizedType,
                data: PPExtraFieldData(content: value)
            )
        }

        let stateValue: Int?
        switch item.state.lowercased() {
        case "active": stateValue = 1
        case "trashed": stateValue = 2
        default: stateValue = nil
        }

        return PPItem(
            itemId: item.id,
            shareId: item.shareId,
            data: PPItemData(metadata: metadata, type: type, content: content, extraFields: extraFields),
            state: stateValue,
            createTime: nil,
            modifyTime: nil,
            pinned: nil,
            aliasEmail: nil
        )
    }
}

// MARK: - Codable Models

private struct PPVaultListResponse: Codable {
    let vaults: [PPVaultInfo]
}

private struct PPItemListResponse: Codable {
    let items: [PPNewItem]
}

private struct PPItemViewResponse: Codable {
    let item: PPNewItem
}

private struct PPNewItem: Codable {
    let id: String?
    let shareId: String?
    let content: PPNewItemContent
    let state: String

    enum CodingKeys: String, CodingKey {
        case id
        case shareId = "share_id"
        case content
        case state
    }
}

private struct PPNewItemContent: Codable {
    let title: String
    let note: String?
    let content: PPNewInnerContent
    let extraFields: [PPNewExtraField]?

    enum CodingKeys: String, CodingKey {
        case title
        case note
        case content
        case extraFields = "extra_fields"
    }
}

private struct PPNewInnerContent: Codable {
    let login: PPNewLoginContent?

    enum CodingKeys: String, CodingKey {
        case login = "Login"
    }
}

private struct PPNewLoginContent: Codable {
    let email: String?
    let username: String?
    let password: String?
    let urls: [String]?
    let totpUri: String?

    enum CodingKeys: String, CodingKey {
        case email
        case username
        case password
        case urls
        case totpUri = "totp_uri"
    }
}

private struct PPNewExtraField: Codable {
    let name: String
    let content: [String: String]
}

public struct PPItem: Codable, Sendable {
    public let itemId: String?
    public let shareId: String?
    public let data: PPItemData
    public let state: Int?                // 1 = active, 2 = trashed
    public let createTime: Int?           // unix timestamp
    public let modifyTime: Int?
    public let pinned: Bool?
    public let aliasEmail: String?
}

public struct PPItemData: Codable, Sendable {
    public let metadata: PPMetadata
    public let type: String              // "login", "creditCard", "note", "alias", "password"
    public let content: PPContent
    public let extraFields: [PPExtraField]?
}

public struct PPMetadata: Codable, Sendable {
    public let name: String
    public let note: String?
}

public struct PPContent: Codable, Sendable {
    public let itemUsername: String?      // empty on ~79% — fallback to itemEmail
    public let itemEmail: String?
    public let password: String?
    public let urls: [String]?           // plain strings, NOT {uri, match} objects
    public let totpUri: String?          // may be empty — check extraFields for type=="totp"
    public let passkeys: [PPPasskey]?
}

public struct PPPasskey: Codable, Sendable {
    // Rarely populated, structure TBD
}

public struct PPExtraField: Codable, Sendable {
    public let fieldName: String         // can be garbage: "SearchText-kind(text)", "Unknown field"
    public let type: String              // "text", "hidden", "totp"
    public let data: PPExtraFieldData
}

public struct PPExtraFieldData: Codable, Sendable {
    public let content: String?          // for type=="totp", this is the otpauth:// URI
}

// ZIP export wrapper (not needed for CLI, but useful for json-source proton format)
public struct PPExport: Codable, Sendable {
    public let encrypted: Bool?
    public let userId: String
    public let version: String
    public let vaults: [String: PPVaultExport] // keyed by vault UUID
}

public struct PPVaultExport: Codable, Sendable {
    public let name: String
    public let description: String
    public let items: [PPItem]
}

public struct PPVaultInfo: Codable, Sendable {
    public let shareId: String?
    public let name: String?

    enum CodingKeys: String, CodingKey {
        case shareId = "share_id"
        case name
    }
}

// MARK: - Errors

public enum ProtonPassError: Error, LocalizedError {
    case cliNotFound
    case loginFailed(String)
    case listFailed(String)
    case viewFailed(String)

    public var errorDescription: String? {
        switch self {
        case .cliNotFound:
            return "ProtonPass CLI not found. Install with `brew install protonpass/tap/pass-cli` or download from proton.me."
        case .loginFailed(let detail):
            if detail.hasPrefix("Proton Pass") || detail.hasPrefix("Your Proton account") {
                return detail
            }
            return "Proton Pass login failed: \(detail)"
        case .listFailed(let detail):
            return "Failed to list Proton Pass items: \(detail)"
        case .viewFailed(let detail):
            return "Failed to view Proton Pass item: \(detail)"
        }
    }
}
