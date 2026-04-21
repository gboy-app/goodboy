// Tool: Reads credentials from ProtonPass CLI.
// Modern pass-cli list returns full login content. Item view is used only as fallback.
// Auth via PROTON_PASS_PASSWORD env var + optional TOTP/extra password.

import Foundation
import os.log
import FlowEngine

public final class ProtonPassCLITool: Tool {

    public static let id = "protonpass"
    public static let name = "ProtonPass CLI"
    public static let description = "Reads credentials from Proton Pass vault via pass-cli"
    public static let supportedTypes: [BoxItemType] = [.password, .otp]

    public static let paramSchema: [ParamSpec] = [
        ParamSpec(key: "username", label: "Proton Email", type: .string, required: true,
                  description: "Proton account email used to sign in",
                  validation: .email),
        ParamSpec(key: "password", label: "Proton Password", type: .keychain, required: true,
                  description: "Proton account password",
                  validation: .minLength(8)),
        ParamSpec(key: "totp", label: "2FA Code", type: .string, required: false,
                  description: "One-time code from your authenticator app",
                  persistence: .transient,
                  validation: .regex("^[0-9]{6}$")),
        ParamSpec(key: "mailboxPassword", label: "Mailbox Password", type: .keychain, required: false,
                  description: "Optional: mailbox password if enabled on your Proton account"),
    ]

    public static var slugPool: [SlugEntry] {
        [SlugEntry(slug: "default", name: "ProtonPass", config: [:])]
    }

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "ProtonPassCLITool")

    private static func isAuthSessionError(_ message: String) -> Bool {
        let lower = message.lowercased()
        return lower.contains("not logged in")
            || lower.contains("requires an authenticated client")
            || lower.contains("session is some but is not logged in")
    }

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
            DataSchemaField(key: "customFields", type: "string", required: false),
        ]
    }

    public func discover() -> [String: Any] {
        var result: [String: Any] = [:]
        guard let binary = ProtonPassCLI.findBinary() else {
            result["cliAvailable"] = false
            return result
        }
        result["cliAvailable"] = true
        result["cliBinary"] = binary
        switch ProtonPassCLI.authStatus() {
        case .authenticated(let email):
            result["authenticated"] = true
            if let email, !email.isEmpty { result["email"] = email }
        case .unauthenticated:
            result["authenticated"] = false
        case .unknown(let detail):
            result["authenticated"] = false
            if !detail.isEmpty { result["authError"] = detail }
        }
        return result
    }

    private static var isAppInstalled: Bool {
        FileManager.default.fileExists(atPath: "/Applications/Proton Pass.app")
    }

    public func suggestDeviceConfigs() -> [[String: String]] {
        // Suggest if app OR CLI is present — device shows not-ready with install instructions if CLI missing.
        guard ProtonPassCLI.isAvailable || Self.isAppInstalled else { return [] }
        var config: [String: String] = [:]
        var name = "ProtonPass"
        if case .authenticated(let email) = ProtonPassCLI.authStatus(),
           let email, !email.isEmpty {
            config["username"] = email
            name = "ProtonPass (\(email))"
        }
        config["_slug"] = "default"
        config["_name"] = name
        config["_canRead"] = "true"
        config["_canWrite"] = "false"
        return [config]
    }

    public func check(params: [String: String]) -> [DeviceError] {
        if !ProtonPassCLI.isAvailable {
            return [DeviceError(category: .notInstalled, message: "ProtonPass CLI not found. Click Install — Goodboy uses Homebrew if available, otherwise downloads the official binary.", action: "Install ProtonPass CLI", actionURL: "https://protonpass.github.io/pass-cli/")]
        }
        if let vault = params["vault"], !vault.isEmpty {
            if vault.contains("\0") {
                return [DeviceError(category: .missingParam, message: "Vault name must not contain null bytes.", action: "Rename vault")]
            }
            if vault.hasPrefix("-") {
                return [DeviceError(category: .missingParam, message: "Vault name must not start with '-' — pass-cli would parse it as a flag.", action: "Rename vault")]
            }
        }
        switch ProtonPassCLI.authStatus() {
        case .authenticated:
            return []
        case .unauthenticated:
            return [DeviceError(category: .authFailed, message: "ProtonPass login required: session is not authenticated. Click the ProtonPass device to enter email, password, and OTP.", action: "Sign in")]
        case .unknown(let detail):
            if detail.isEmpty { return [] }
            return [DeviceError(category: .notRunning, message: "Could not determine ProtonPass auth state: \(detail)", action: "Retry")]
        }
    }

    public func connect(params: [String: String]) throws {
        guard ProtonPassCLI.isAvailable else {
            throw ToolError("ProtonPass CLI not found. Install pass-cli first.")
        }
        ProtonPassCLI.invalidateAuthCache()
        if case .authenticated = ProtonPassCLI.authStatus() { return }

        let username = (params["username"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let password = (params["password"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else { throw ToolError("Proton Email is required.") }
        guard !password.isEmpty else { throw ToolError("Proton Password is required.") }

        let totp = params["totp"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let mailboxPassword = params["mailboxPassword"]?.trimmingCharacters(in: .whitespacesAndNewlines)

        do {
            try ProtonPassCLI.loginInteractive(
                username: username, password: password,
                totp: totp?.isEmpty == false ? totp : nil,
                extraPassword: mailboxPassword?.isEmpty == false ? mailboxPassword : nil
            )
        } catch let error as CLIRunnerError where error.isTimeout {
            let hasTOTP = totp?.isEmpty == false
            let message = hasTOTP
                ? "Login timed out — check your network connection and try again."
                : "Login timed out. If your account uses 2FA, enter your one-time code and retry."
            throw ToolError(message)
        }

        if case .authenticated = ProtonPassCLI.authStatus() { return }
        throw ToolError("Login completed but session is not authenticated. Try again with a fresh 2FA code.")
    }

    // MARK: - Execute

    public func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        guard action == .read else {
            return .failure("ProtonPassCLITool is a source — use action: .read to import from Proton Pass.")
        }

        // Invalidate cached auth status — execute may login/retry
        ProtonPassCLI.invalidateAuthCache()

        let username = params["username"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = params["password"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        let totp = params["totp"]
        let mailboxPassword = params["mailboxPassword"]
        let vault = params["vault"]

        // 1. Login only when session is not authenticated.
        switch ProtonPassCLI.authStatus() {
        case .authenticated:
            break
        case .unauthenticated:
            guard !username.isEmpty else {
                return .failure("ProtonPass login required: missing Proton Email.")
            }
            guard !password.isEmpty else {
                return .failure("ProtonPass login required: missing Proton Password in Keychain.")
            }
            do {
                try ProtonPassCLI.loginInteractive(
                    username: username,
                    password: password,
                    totp: totp,
                    extraPassword: mailboxPassword
                )
            } catch {
                return .failure(error.localizedDescription)
            }
        case .unknown:
            if !username.isEmpty && !password.isEmpty {
                do {
                    try ProtonPassCLI.loginInteractive(
                        username: username,
                        password: password,
                        totp: totp,
                        extraPassword: mailboxPassword
                    )
                } catch {
                    return .failure(error.localizedDescription)
                }
            } else {
                return .failure("Could not determine ProtonPass auth state. Provide your Proton Email and Password in device settings.")
            }
        }

        // 2. List items
        let items: [PPItem]
        do {
            items = try ProtonPassCLI.listItems(vault: vault)
        } catch {
            let details = error.localizedDescription
            if Self.isAuthSessionError(details) {
                do {
                    guard !username.isEmpty else {
                        return .failure("ProtonPass session expired and Proton Email is missing. Click ProtonPass device and enter email.")
                    }
                    guard !password.isEmpty else {
                        return .failure("ProtonPass session expired and Proton Password is missing. Click ProtonPass device and enter password.")
                    }
                    // One retry: refresh auth session, then re-list.
                    try ProtonPassCLI.loginInteractive(
                        username: username,
                        password: password,
                        totp: totp,
                        extraPassword: mailboxPassword
                    )
                    items = try ProtonPassCLI.listItems(vault: vault)
                } catch {
                    return .failure(error.localizedDescription)
                }
            } else {
                return .failure(details)
            }
        }

        // 3. Filter: active login items only
        let loginItems = items.filter { item in
            // Exclude trashed (state == 2)
            if item.state == 2 { return false }
            // Only login type
            return item.data.type == "login"
        }

        Self.log.info("Found \(loginItems.count) login items out of \(items.count) total")

        // 4. Build BoxItem payloads; fetch full item only when list output lacks secrets.
        var credentials: [BoxItem] = []
        var warnings: [String] = []
        var fetchErrors = 0

        let trashedCount = items.filter { $0.state == 2 }.count
        let aliasCount = items.filter { $0.data.type == "alias" }.count
        let noteCount = items.filter { $0.data.type == "note" }.count

        for (index, item) in loginItems.enumerated() {
            if index > 0 && index % 50 == 0 {
                Self.log.info("Fetching item \(index)/\(loginItems.count)...")
            }

            // Modern pass-cli list output already includes password/totp in most cases.
            // Only fall back to item view when secret fields are missing.
            let fullItem: PPItem
            let hasInlineSecret = (item.data.content.password?.isEmpty == false)
                || (item.data.content.totpUri?.isEmpty == false)

            if !hasInlineSecret, let shareId = item.shareId, let itemId = item.itemId {
                do {
                    fullItem = try ProtonPassCLI.viewItem(shareId: shareId, itemId: itemId)
                } catch {
                    fetchErrors += 1
                    Self.log.warning("Failed to fetch item \(item.data.metadata.name): \(error.localizedDescription)")
                    // Fall back to summary data
                    fullItem = item
                }
            } else {
                fullItem = item
            }

            let boxItem = Self.mapPPItemToBoxItem(fullItem)
            credentials.append(boxItem)
        }

        if fetchErrors > 0 {
            warnings.append("Failed to fetch \(fetchErrors) item(s) — used summary data as fallback")
        }
        if trashedCount > 0 {
            warnings.append("Excluded \(trashedCount) trashed item(s)")
        }
        if aliasCount > 0 {
            warnings.append("Skipped \(aliasCount) alias(es)")
        }
        if noteCount > 0 {
            warnings.append("Skipped \(noteCount) secure note(s)")
        }

        let otpCount = credentials.filter { $0.extras["otpAuth"] != nil }.count
        if otpCount > 0 {
            warnings.append("\(otpCount) entries with OTP")
        }

        // 5. Append to SecuredBox
        securedBox.append(credentials)
        Self.log.info("Loaded \(credentials.count) credentials from Proton Pass CLI")

        return .success(
            count: credentials.count,
            message: "Read \(credentials.count) credentials from Proton Pass vault",
            warnings: warnings
        )
    }

    // MARK: - Mapping

    /// Map a PPItem to BoxItem. Handles all 5 documented anomalies.
    static func mapPPItemToBoxItem(_ item: PPItem) -> BoxItem {
        let content = item.data.content

        // URL: plain strings array
        let url = content.urls?.first ?? ""

        // Username: prefer itemUsername if non-empty, fallback to itemEmail
        let username: String
        if let itemUsername = content.itemUsername, !itemUsername.isEmpty {
            username = itemUsername
        } else {
            username = content.itemEmail ?? ""
        }

        let password = content.password ?? ""

        var extras: [String: String] = [:]
        extras["title"] = item.data.metadata.name

        // OTP: check totpUri first, then scan extraFields for type=="totp"
        if let totpUri = content.totpUri, !totpUri.isEmpty {
            extras["otpAuth"] = totpUri
        } else if let extraFields = item.data.extraFields {
            if let totpField = extraFields.first(where: { $0.type == "totp" }),
               let totpContent = totpField.data.content, !totpContent.isEmpty {
                extras["otpAuth"] = totpContent
            }
        }

        if let note = item.data.metadata.note, !note.isEmpty {
            extras["notes"] = note
        }

        // Custom fields (text/hidden, excluding totp which was already hoisted)
        if let extraFields = item.data.extraFields {
            let customFields = extraFields.filter { $0.type != "totp" }
            if !customFields.isEmpty {
                let fieldDicts = customFields.map { field -> [String: String] in
                    var d: [String: String] = [
                        "name": field.fieldName,
                        "type": field.type,
                    ]
                    if let value = field.data.content {
                        d["value"] = value
                    }
                    return d
                }
                if let jsonData = try? JSONSerialization.data(withJSONObject: fieldDicts),
                   let jsonStr = String(data: jsonData, encoding: .utf8) {
                    extras["customFields"] = jsonStr
                }
            }
        }

        return BoxItem(url: url, username: username, password: password, extras: extras)
    }
}
