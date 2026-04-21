// Unified error types for KeePassXC CLI and XML operations.

import Foundation
import FlowEngine

public enum KeePassError: Error, LocalizedError {

    // MARK: - CLI
    case cliNotFound
    case cliExecFailed(String)
    case cliInvalidOutput(String)
    case dbPathRequired

    // MARK: - XML / JSON
    case xmlParseFailed(String)
    case jsonParseFailed(String)

    // MARK: - General
    case notRunning
    case databaseLocked
    case databaseClosed

    public var errorDescription: String? {
        switch self {
        // CLI
        case .cliNotFound:
            return "keepassxc-cli not found. Install KeePassXC from https://keepassxc.org or set GOODBOY_KEEPASSXC_CLI_PATH."
        case .cliExecFailed(let detail):
            return "keepassxc-cli failed: \(detail)"
        case .cliInvalidOutput(let detail):
            return "keepassxc-cli output invalid: \(detail)"
        case .dbPathRequired:
            return "Database path required. Provide the path to your .kdbx file in device setup."

        // XML / JSON
        case .xmlParseFailed(let detail):
            return "XML parse failed: \(detail)"
        case .jsonParseFailed(let detail):
            return "JSON parse failed: \(detail)"

        // General
        case .notRunning:
            return "KeePassXC is not running. Open KeePassXC and unlock a database, then try again."
        case .databaseLocked:
            return "KeePassXC database is locked. Unlock it in KeePassXC and try again."
        case .databaseClosed:
            return "No database is open in KeePassXC. Open a database and try again."
        }
    }
}
