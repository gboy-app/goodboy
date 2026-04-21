// Tool: Reads credentials from Bitwarden CLI.
// Single-call data fetch — `bw list items` returns full items with secrets.

import Foundation
import os.log
import FlowEngine

public final class BitwardenCLITool: Tool {

    public static let id = "bitwarden"
    public static let name = "Bitwarden CLI"
    public static let description = "Reads credentials from Bitwarden vault via bw CLI"
    public static let supportedTypes: [BoxItemType] = [.password, .otp]

    public static let paramSchema: [ParamSpec] = [
        ParamSpec(key: "masterPassword", label: "Master Password", type: .keychain, required: true,
                  description: "Bitwarden master password"),
        ParamSpec(key: "serverUrl", label: "Server URL", type: .choice, required: false,
                  description: "Bitwarden server URL (set EU if your account is on vault.bitwarden.eu)",
                  choices: ["https://vault.bitwarden.com", "https://vault.bitwarden.eu"],
                  choiceLabels: [".com", ".eu"]),
        ParamSpec(key: "clientId", label: "API Client ID", type: .keychain, required: false,
                  description: "Bitwarden API client_id (needed if not already logged in)"),
        ParamSpec(key: "clientSecret", label: "API Client Secret", type: .keychain, required: false,
                  description: "Bitwarden API client_secret (needed if not already logged in)"),
    ]

    public static var slugPool: [SlugEntry] {
        [SlugEntry(slug: "default", name: "Bitwarden", config: [:])]
    }

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "BitwardenCLITool")

    public init() {}

    public func canRead(slug: String) -> Bool { true }
    public func canWrite(slug: String) -> Bool { false }

    public func dataSchema(params: [String: String]) -> [DataSchemaField] {
        [
            DataSchemaField(key: "url", type: "url", required: true),
            DataSchemaField(key: "username", type: "string", required: true),
            DataSchemaField(key: "password", type: "secret", required: true),
            DataSchemaField(key: "otpAuth", type: "secret", required: false),
            DataSchemaField(key: "notes", type: "string", required: false),
            DataSchemaField(key: "title", type: "string", required: false),
            DataSchemaField(key: "folderId", type: "string", required: false),
            DataSchemaField(key: "customFields", type: "string", required: false),
        ]
    }

    public func discover() -> [String: Any] {
        var result: [String: Any] = [:]
        guard let binary = BitwardenCLI.findBinary() else {
            result["cliAvailable"] = false
            return result
        }
        result["cliAvailable"] = true
        result["cliBinary"] = binary

        // bw status is cheap — no auth needed, returns vault state + email
        if let status = try? BitwardenCLI.status() {
            result["vaultStatus"] = status.status
            if let email = status.userEmail { result["userEmail"] = email }
            if let lastSync = status.lastSync { result["lastSync"] = lastSync }
        }
        return result
    }

    private static var isAppInstalled: Bool {
        FileManager.default.fileExists(atPath: "/Applications/Bitwarden.app")
    }

    public func suggestDeviceConfigs() -> [[String: String]] {
        // Suggest if app OR CLI is present — device shows not-ready with install instructions if CLI missing.
        guard BitwardenCLI.isAvailable || Self.isAppInstalled else { return [] }
        return [["_slug": "default", "_name": "Bitwarden", "_canRead": "true", "_canWrite": "false"]]
    }

    public func check(params: [String: String]) -> [DeviceError] {
        if !BitwardenCLI.isAvailable {
            return [DeviceError(category: .notInstalled, message: "Bitwarden CLI not found. Click Install — Goodboy uses Homebrew if available, otherwise downloads the official binary.", action: "Install Bitwarden CLI")]
        }
        let status: BWStatus
        do {
            status = try BitwardenCLI.status()
        } catch {
            return [DeviceError(category: .notRunning, message: "Could not check Bitwarden status: \(error.localizedDescription)", action: "Retry")]
        }

        if status.status == "unauthenticated" {
            return [DeviceError(category: .authFailed, message: "Bitwarden is not logged in. Open device settings and add API Client ID + API Client Secret.", action: "Add API keys")]
        }
        return []
    }

    public func connect(params: [String: String]) throws {
        guard BitwardenCLI.isAvailable else {
            throw ToolError("Bitwarden CLI not found. Install with: brew install bitwarden-cli")
        }

        let masterPassword = params["masterPassword"] ?? ""
        guard !masterPassword.isEmpty else {
            throw ToolError("Missing master password. Set it in device settings.")
        }

        let serverUrl = params["serverUrl"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let clientId = params["clientId"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let clientSecret = params["clientSecret"]?.trimmingCharacters(in: .whitespacesAndNewlines)

        if let serverUrl, !serverUrl.isEmpty {
            try BitwardenCLI.configServer(url: serverUrl)
        }

        BitwardenCLI.invalidateStatusCache()
        let status = try BitwardenCLI.status()

        if status.status == "unauthenticated" {
            guard let clientId, !clientId.isEmpty,
                  let clientSecret, !clientSecret.isEmpty else {
                throw ToolError("Bitwarden is not logged in. Add API Client ID + Secret, or run `bw login` in Terminal first.")
            }
            if let serverUrl, !serverUrl.isEmpty {
                try BitwardenCLI.loginAPIKey(clientId: clientId, clientSecret: clientSecret)
            } else {
                let candidates = ["https://vault.bitwarden.eu", "https://vault.bitwarden.com"]
                var lastError: Error?
                var didLogin = false
                for candidate in candidates {
                    do {
                        try BitwardenCLI.configServer(url: candidate)
                        try BitwardenCLI.loginAPIKey(clientId: clientId, clientSecret: clientSecret)
                        didLogin = true
                        break
                    } catch { lastError = error }
                }
                if !didLogin {
                    throw ToolError(lastError?.localizedDescription ?? "Failed to log in with Bitwarden API key.")
                }
            }
        }

        let session = try BitwardenCLI.unlock(password: masterPassword)
        _ = session
        // Don't lock here — execute() needs the vault unlocked and locks in its defer.
        // Locking here caused rapid lock→unlock cycling that confused the bw CLI.
        BitwardenCLI.invalidateStatusCache()
    }

    // MARK: - Execute

    public func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        guard action == .read else {
            return .failure("BitwardenCLITool is a source — use action: .read to import from Bitwarden.")
        }

        guard let masterPassword = params["masterPassword"], !masterPassword.isEmpty else {
            return .failure("Missing 'masterPassword'. Set it via goodboy_keychain_set.")
        }
        let serverUrl = params["serverUrl"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let clientId = params["clientId"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let clientSecret = params["clientSecret"]?.trimmingCharacters(in: .whitespacesAndNewlines)

        // Configure server early to avoid region mismatch (EU vs COM) for API-key login.
        if let serverUrl, !serverUrl.isEmpty {
            do {
                try BitwardenCLI.configServer(url: serverUrl)
            } catch {
                return .failure(error.localizedDescription)
            }
        }

        // 1. Check vault status (fresh — don't trust cache during execute)
        BitwardenCLI.invalidateStatusCache()
        let status: BWStatus
        do {
            status = try BitwardenCLI.status()
        } catch {
            return .failure("Could not check Bitwarden status: \(error.localizedDescription)")
        }

        if status.status == "unauthenticated" {
            guard
                let clientId, !clientId.isEmpty,
                let clientSecret, !clientSecret.isEmpty
            else {
                return .failure("Bitwarden is not logged in for Goodboy. Set 'clientId' and 'clientSecret' in device settings, then retry.")
            }

            if let serverUrl, !serverUrl.isEmpty {
                do {
                    try BitwardenCLI.loginAPIKey(clientId: clientId, clientSecret: clientSecret)
                } catch {
                    return .failure(error.localizedDescription)
                }
            } else {
                // No server selected yet. Try common Bitwarden cloud regions.
                // This avoids forcing a manual "server URL" setup step on first run.
                let candidates = ["https://vault.bitwarden.eu", "https://vault.bitwarden.com"]
                var lastError: Error?
                var didLogin = false

                for candidate in candidates {
                    do {
                        try BitwardenCLI.configServer(url: candidate)
                        try BitwardenCLI.loginAPIKey(clientId: clientId, clientSecret: clientSecret)
                        didLogin = true
                        break
                    } catch {
                        lastError = error
                    }
                }

                if !didLogin {
                    if let lastError {
                        return .failure("\(lastError.localizedDescription). If your account is self-hosted, set 'serverUrl' in device settings and retry.")
                    }
                    return .failure("Failed to log in with Bitwarden API key.")
                }
            }
        }

        // 2. Unlock vault → session token
        let session: String
        do {
            session = try BitwardenCLI.unlock(password: masterPassword)
        } catch {
            return .failure("Failed to unlock Bitwarden vault: \(error.localizedDescription)")
        }

        // Always lock after use, and invalidate cached status
        defer {
            try? BitwardenCLI.lock()
            BitwardenCLI.invalidateStatusCache()
        }

        // 3. Sync to ensure latest data
        do {
            try BitwardenCLI.sync(session: session)
        } catch {
            Self.log.warning("Sync failed (continuing with cached data): \(error.localizedDescription)")
        }

        // 4. List all items
        let items: [BWItem]
        do {
            items = try BitwardenCLI.listItems(session: session)
        } catch {
            return .failure("Failed to list Bitwarden items: \(error.localizedDescription)")
        }

        // 5. Filter to LOGIN type (1) and non-deleted, map to BoxItem
        var credentials: [BoxItem] = []
        var warnings: [String] = []
        var skippedNotes = 0
        var skippedOther = 0

        for item in items {
            // Skip deleted items
            if item.deletedDate != nil { continue }

            // Only process LOGIN type
            guard item.type == 1 else {
                if item.type == 2 { skippedNotes += 1 }
                else { skippedOther += 1 }
                continue
            }

            guard let login = item.login else { continue }

            let url = login.uris?.first(where: { $0.uri != nil })?.uri ?? ""
            let username = login.username ?? ""
            let password = login.password ?? ""

            var extras: [String: String] = [:]
            extras["title"] = item.name

            if let totp = login.totp, !totp.isEmpty {
                extras["otpAuth"] = totp
            }
            if let notes = item.notes, !notes.isEmpty {
                extras["notes"] = notes
            }
            if let folderId = item.folderId, !folderId.isEmpty {
                extras["folderId"] = folderId
            }

            // Custom fields → JSON string
            if let fields = item.fields, !fields.isEmpty {
                let fieldDicts = fields.map { field -> [String: String] in
                    var d: [String: String] = ["type": String(field.type)]
                    if let name = field.name { d["name"] = name }
                    if let value = field.value { d["value"] = value }
                    return d
                }
                if let jsonData = try? JSONSerialization.data(withJSONObject: fieldDicts),
                   let jsonStr = String(data: jsonData, encoding: .utf8) {
                    extras["customFields"] = jsonStr
                }
            }

            credentials.append(BoxItem(url: url, username: username, password: password, extras: extras))
        }

        if skippedNotes > 0 {
            warnings.append("Skipped \(skippedNotes) secure note(s)")
        }
        if skippedOther > 0 {
            warnings.append("Skipped \(skippedOther) non-login item(s) (cards, identities, etc.)")
        }

        let otpCount = credentials.filter { $0.extras["otpAuth"] != nil }.count
        if otpCount > 0 {
            warnings.append("\(otpCount) entries with OTP")
        }

        // 6. Append to SecuredBox
        securedBox.append(credentials)
        Self.log.info("Loaded \(credentials.count) credentials from Bitwarden CLI")

        return .success(
            count: credentials.count,
            message: "Read \(credentials.count) credentials from Bitwarden vault",
            warnings: warnings
        )
    }
}
