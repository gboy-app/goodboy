// Tool: Reads credentials from 1Password CLI.
// N+1 pattern: list items (summaries) → get each item (with secrets).
// Auth via OP_SERVICE_ACCOUNT_TOKEN or existing `op signin` session.

import Foundation
import os.log
import FlowEngine

public final class OnePasswordCLITool: Tool {

    public static let id = "onepassword"
    public static let name = "1Password CLI"
    public static let description = "Reads credentials from 1Password vault via op CLI"
    public static let supportedTypes: [BoxItemType] = [.password, .otp]

    public static let paramSchema: [ParamSpec] = [
        ParamSpec(key: "serviceAccountToken", label: "Service Account Token", type: .keychain, required: false,
                  description: "If set, uses OP_SERVICE_ACCOUNT_TOKEN to authenticate non-interactively (best for automation/CI)"),
    ]

    public static var slugPool: [SlugEntry] {
        [SlugEntry(slug: "default", name: "1Password", config: [:])]
    }

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "OnePasswordCLITool")

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
            DataSchemaField(key: "vault", type: "string", required: false),
            DataSchemaField(key: "tags", type: "string", required: false),
            DataSchemaField(key: "customFields", type: "string", required: false),
        ]
    }

    public func discover() -> [String: Any] {
        var result: [String: Any] = [:]
        guard let binary = OnePasswordCLI.findBinary() else {
            result["cliAvailable"] = false
            return result
        }
        result["cliAvailable"] = true
        result["cliBinary"] = binary

        // With App Integration, `op account list` is the reliable way to check
        // if the CLI is connected to the desktop app and an account exists.
        if let accounts = try? OnePasswordCLI.accountList(), let account = accounts.first {
            if let email = account.email { result["userEmail"] = email }
            if let url = account.url { result["accountUrl"] = url }
        }
        return result
    }

    private static var isAppInstalled: Bool {
        FileManager.default.fileExists(atPath: "/Applications/1Password.app")
    }

    public func suggestDeviceConfigs() -> [[String: String]] {
        // Suggest if app OR CLI is present — device shows not-ready with install instructions if CLI missing.
        guard OnePasswordCLI.isAvailable || Self.isAppInstalled else { return [] }
        return [["_slug": "default", "_name": "1Password", "_canRead": "true", "_canWrite": "false"]]
    }

    public func check(params: [String: String]) -> [DeviceError] {
        // Only check if the CLI binary exists. Do NOT probe accountList() here —
        // that triggers a macOS permission prompt ("access data from other apps")
        // on every app launch. Auth is checked in connect() when the user acts.
        if !OnePasswordCLI.isAvailable {
            return [DeviceError(category: .notInstalled, message: "1Password CLI not found. Click Install — requires Homebrew.", action: "Install 1Password CLI", actionURL: "https://1password.com/downloads/command-line/")]
        }
        return []
    }

    public func connect(params: [String: String]) throws {
        guard OnePasswordCLI.isAvailable else {
            throw ToolError("1Password CLI not found. Install with: brew install 1password-cli")
        }
        let token = (params["serviceAccountToken"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if token.isEmpty {
            let accounts = try OnePasswordCLI.accountList()
            if accounts.isEmpty {
                throw ToolError("No 1Password accounts found. Open 1Password → Settings → Developer and enable 'Integrate with 1Password CLI'.")
            }
            try OnePasswordCLI.signin()
        } else {
            _ = try OnePasswordCLI.whoami(serviceAccountToken: token)
        }
    }

    // MARK: - Execute

    public func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        guard action == .read else {
            return .failure("OnePasswordCLITool is a source — use action: .read to import from 1Password.")
        }

        let serviceAccountToken = params["serviceAccountToken"]

        // 1. Verify connection
        if let token = serviceAccountToken, !token.isEmpty {
            // If explicit token provided, test it
            do {
                _ = try OnePasswordCLI.whoami(serviceAccountToken: token)
            } catch {
                return .failure("1Password token auth failed: \(error.localizedDescription)")
            }
        } else {
            // App Integration path: just verify accounts exist
            do {
                let accounts = try OnePasswordCLI.accountList()
                if accounts.isEmpty {
                    return .failure("No 1Password accounts found. Ensure App Integration is enabled in the 1Password desktop app.")
                }
            } catch {
                return .failure("Failed to connect to 1Password: \(error.localizedDescription). Ensure the 1Password desktop app is running and App Integration is enabled in Settings -> Developer.")
            }
        }

        // 2. List items (summaries only) - This triggers the biometric prompt if needed
        let summaries: [OPItemSummary]
        do {
            summaries = try OnePasswordCLI.listItems(vault: nil, serviceAccountToken: serviceAccountToken)
        } catch {
            return .failure("Failed to list 1Password items: \(error.localizedDescription)")
        }

        // Filter to LOGIN and PASSWORD categories
        let loginCategories: Set<String> = ["LOGIN", "PASSWORD"]
        let loginSummaries = summaries.filter { loginCategories.contains($0.category) }

        Self.log.info("Found \(loginSummaries.count) login items out of \(summaries.count) total")

        // 3. Fetch each item (N+1 — op doesn't return secrets in list)
        var credentials: [BoxItem] = []
        var warnings: [String] = []
        var fetchErrors = 0

        for (index, summary) in loginSummaries.enumerated() {
            if index > 0 && index % 50 == 0 {
                Self.log.info("Fetching item \(index)/\(loginSummaries.count)...")
            }

            let item: OPItem
            do {
                item = try OnePasswordCLI.getItem(id: summary.id, serviceAccountToken: serviceAccountToken)
            } catch {
                fetchErrors += 1
                Self.log.warning("Failed to fetch item \(summary.id) (\(summary.title)): \(error.localizedDescription)")
                continue
            }

            // 4. Map fields to BoxItem
            let username = item.fields?.first { $0.label == "username" }?.value ?? ""
            let password = item.fields?.first { $0.type == "CONCEALED" && ($0.label == "password" || $0.label == nil) }?.value ?? ""

            // URL: prefer item.urls[primary], then fields with type URL
            let url: String
            if let primaryUrl = item.urls?.first(where: { $0.primary == true })?.href {
                url = primaryUrl
            } else if let firstUrl = item.urls?.first?.href {
                url = firstUrl
            } else if let fieldUrl = item.fields?.first(where: { $0.type == "URL" })?.value {
                url = fieldUrl
            } else {
                url = ""
            }

            let otp = item.fields?.first { $0.type == "OTP" }?.value

            var extras: [String: String] = [:]
            extras["title"] = item.title
            if let vaultName = item.vault.name {
                extras["vault"] = vaultName
            }
            if let otp = otp, !otp.isEmpty {
                extras["otpAuth"] = otp
            }
            if let tags = item.tags, !tags.isEmpty {
                extras["tags"] = tags.joined(separator: ",")
            }

            // Notes field
            if let notesField = item.fields?.first(where: { $0.id == "notesPlain" || $0.label == "notes" || $0.label == "notesPlain" }),
               let notes = notesField.value, !notes.isEmpty {
                extras["notes"] = notes
            }

            // Section-grouped custom fields → JSON
            let standardLabels: Set<String?> = ["username", "password", "notes", "notesPlain", nil]
            let standardTypes: Set<String> = ["OTP", "URL"]
            let customFields = item.fields?.filter { field in
                !standardLabels.contains(field.label) && !standardTypes.contains(field.type) && field.id != "notesPlain"
            } ?? []
            if !customFields.isEmpty {
                let fieldDicts = customFields.map { field -> [String: String] in
                    var d: [String: String] = ["type": field.type]
                    if let label = field.label { d["label"] = label }
                    if let value = field.value { d["value"] = value }
                    if let section = field.section?.label { d["section"] = section }
                    return d
                }
                if let jsonData = try? JSONSerialization.data(withJSONObject: fieldDicts),
                   let jsonStr = String(data: jsonData, encoding: .utf8) {
                    extras["customFields"] = jsonStr
                }
            }

            credentials.append(BoxItem(url: url, username: username, password: password, extras: extras))
        }

        if fetchErrors > 0 {
            warnings.append("Failed to fetch \(fetchErrors) item(s)")
        }

        let skippedCount = summaries.count - loginSummaries.count
        if skippedCount > 0 {
            warnings.append("Skipped \(skippedCount) non-login item(s)")
        }

        let otpCount = credentials.filter { $0.extras["otpAuth"] != nil }.count
        if otpCount > 0 {
            warnings.append("\(otpCount) entries with OTP")
        }

        // 5. Append to SecuredBox
        securedBox.append(credentials)
        Self.log.info("Loaded \(credentials.count) credentials from 1Password CLI")

        return .success(
            count: credentials.count,
            message: "Read \(credentials.count) credentials from 1Password vault",
            warnings: warnings
        )
    }
}
