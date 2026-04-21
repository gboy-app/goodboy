// Wraps `op` (1Password CLI) subprocess calls for vault access.
// Primarily uses "App Integration" (biometric via desktop app).
// N+1 pattern: `op item list` returns summaries, `op item get` per item for secrets.

import Foundation
import os.log
import FlowEngine

public final class OnePasswordCLI: Sendable {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "OnePasswordCLI")

    // MARK: - Binary location

    public static func findBinary() -> String? {
        CLIRunner.findBinary(
            envKey: "GOODBOY_OP_CLI_PATH",
            standardPaths: [
                "/opt/homebrew/bin/op",   // arm64
                "/usr/local/bin/op",      // x86
            ],
            whichName: "op",
            expectedTeamIds: ["2BUA8C4S2C"]   // AgileBits Inc.
        )
    }

    public static var isAvailable: Bool {
        findBinary() != nil
    }

    // MARK: - Auth check

    /// Check auth status. Returns account info. Note: With App Integration, `whoami` often fails even when connected. 
    /// Use `accountList` instead to verify connection.
    public static func whoami(serviceAccountToken: String? = nil) throws -> OPAccount {
        guard let binary = findBinary() else {
            throw OnePasswordError.cliNotFound
        }
        var env: [String: String] = [:]
        if let token = serviceAccountToken, !token.isEmpty {
            env["OP_SERVICE_ACCOUNT_TOKEN"] = token
        }
        return try CLIRunner.runJSON(
            binary: binary,
            arguments: ["whoami", "--format", "json"],
            environment: env,
            as: OPAccount.self
        )
    }

    /// List connected accounts. This is the reliable way to verify App Integration is working.
    public static func accountList(serviceAccountToken: String? = nil) throws -> [OPAccount] {
        guard let binary = findBinary() else {
            throw OnePasswordError.cliNotFound
        }
        var env: [String: String] = [:]
        if let token = serviceAccountToken, !token.isEmpty {
            env["OP_SERVICE_ACCOUNT_TOKEN"] = token
        }
        return try CLIRunner.runJSON(
            binary: binary,
            arguments: ["account", "list", "--format", "json"],
            environment: env,
            as: [OPAccount].self
        )
    }

    /// Explicitly trigger the biometric sign-in prompt.
    /// Routes through CLIRunner so the subprocess inherits the same
    /// env allowlist, timeout, SIGKILL-escalation, and stderr-redaction
    /// policies as every other `op` call (L1).
    public static func signin(serviceAccountToken: String? = nil) throws {
        guard let binary = findBinary() else {
            throw OnePasswordError.cliNotFound
        }
        var env: [String: String] = [:]
        if let token = serviceAccountToken, !token.isEmpty {
            env["OP_SERVICE_ACCOUNT_TOKEN"] = token
        }
        let result = try CLIRunner.run(
            binary: binary,
            arguments: ["signin"],
            environment: env,
            timeout: 60
        )
        if result.exitCode != 0 {
            throw OnePasswordError.authFailed("Sign in prompt was canceled or failed")
        }
    }

    // MARK: - Data access

    /// List items (summaries only — no secrets). Optional vault filter.
    public static func listItems(vault: String? = nil, serviceAccountToken: String? = nil) throws -> [OPItemSummary] {
        guard let binary = findBinary() else {
            throw OnePasswordError.cliNotFound
        }
        var args = ["item", "list", "--format", "json"]
        if let vault = vault, !vault.isEmpty {
            args.append(contentsOf: ["--vault", vault])
        }
        var env: [String: String] = [:]
        if let token = serviceAccountToken, !token.isEmpty {
            env["OP_SERVICE_ACCOUNT_TOKEN"] = token
        }
        return try CLIRunner.runJSON(
            binary: binary,
            arguments: args,
            environment: env,
            as: [OPItemSummary].self,
            timeout: 60
        )
    }

    /// Get full item with secrets.
    public static func getItem(id: String, serviceAccountToken: String? = nil) throws -> OPItem {
        guard let binary = findBinary() else {
            throw OnePasswordError.cliNotFound
        }
        var env: [String: String] = [:]
        if let token = serviceAccountToken, !token.isEmpty {
            env["OP_SERVICE_ACCOUNT_TOKEN"] = token
        }
        return try CLIRunner.runJSON(
            binary: binary,
            arguments: ["item", "get", id, "--format", "json"],
            environment: env,
            as: OPItem.self,
            timeout: 30
        )
    }

    /// List available vaults.
    public static func listVaults(serviceAccountToken: String? = nil) throws -> [OPVault] {
        guard let binary = findBinary() else {
            throw OnePasswordError.cliNotFound
        }
        var env: [String: String] = [:]
        if let token = serviceAccountToken, !token.isEmpty {
            env["OP_SERVICE_ACCOUNT_TOKEN"] = token
        }
        return try CLIRunner.runJSON(
            binary: binary,
            arguments: ["vault", "list", "--format", "json"],
            environment: env,
            as: [OPVault].self
        )
    }
}

// MARK: - Codable Models

/// Full item from `op item get` (includes secrets in fields)
public struct OPItem: Codable, Sendable {
    public let id: String
    public let title: String
    public let vault: OPVault
    public let category: String       // "LOGIN", "PASSWORD", "SECURE_NOTE", etc.
    public let favorite: Bool?
    public let tags: [String]?
    public let fields: [OPField]?
    public let createdAt: String?
    public let updatedAt: String?
    public let urls: [OPURL]?

    enum CodingKeys: String, CodingKey {
        case id, title, vault, category, favorite, tags, fields, urls
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

/// Item summary from `op item list` (no secrets)
public struct OPItemSummary: Codable, Sendable {
    public let id: String
    public let title: String
    public let vault: OPVault
    public let category: String
    public let favorite: Bool?
    public let tags: [String]?
    public let createdAt: String?
    public let updatedAt: String?
    public let urls: [OPURL]?

    enum CodingKeys: String, CodingKey {
        case id, title, vault, category, favorite, tags, urls
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

public struct OPVault: Codable, Sendable {
    public let id: String
    public let name: String?
}

public struct OPField: Codable, Sendable {
    public let id: String?
    public let type: String           // "STRING", "CONCEALED", "URL", "OTP", "EMAIL", "REFERENCE"
    public let label: String?
    public let value: String?
    public let section: OPSection?
}

public struct OPSection: Codable, Sendable {
    public let id: String?
    public let label: String?
}

public struct OPURL: Codable, Sendable {
    public let href: String?
    public let primary: Bool?
}

public struct OPAccount: Codable, Sendable {
    public let url: String?
    public let email: String?
    public let user_uuid: String?
    public let account_uuid: String?
}

// MARK: - Errors

public enum OnePasswordError: Error, LocalizedError {
    case cliNotFound
    case authFailed(String)
    case listFailed(String)
    case getItemFailed(String)

    public var errorDescription: String? {
        switch self {
        case .cliNotFound:
            return "1Password CLI not found. Install with `brew install 1password-cli` or set GOODBOY_OP_CLI_PATH."
        case .authFailed(let detail):
            return "1Password auth failed: \(detail). Check your service account token or run `op signin`."
        case .listFailed(let detail):
            return "Failed to list 1Password items: \(detail)"
        case .getItemFailed(let detail):
            return "Failed to get 1Password item: \(detail)"
        }
    }
}
