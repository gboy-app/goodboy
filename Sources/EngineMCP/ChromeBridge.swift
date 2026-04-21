import Foundation

/// Bridge between MCP handlers and Chrome-specific helpers in ProTools.
/// Mode 1 (SwiftUI app) registers a concrete implementation at startup;
/// Mode 2 (standalone `goodboy-mcp`) leaves it nil so the handler returns
/// an "install the app" error without linking any Pro code.
public protocol ChromeBridge: Sendable {
    var isInstalled: Bool { get }
    var isRunning: Bool { get }
    func listProfiles() throws -> [ChromeProfileRow]
    func extractBrowserKey(chromeDir: String) throws -> String
}

public struct ChromeProfileRow: Sendable {
    public let folder: String
    public let name: String
    public let email: String
    public let syncMode: String
    public let recommended: Bool
    public let loginDataLogins: Int
    public let loginDataMetadata: Int
    public let ldfaLogins: Int
    public let ldfaMetadata: Int

    public init(
        folder: String, name: String, email: String,
        syncMode: String, recommended: Bool,
        loginDataLogins: Int, loginDataMetadata: Int,
        ldfaLogins: Int, ldfaMetadata: Int
    ) {
        self.folder = folder
        self.name = name
        self.email = email
        self.syncMode = syncMode
        self.recommended = recommended
        self.loginDataLogins = loginDataLogins
        self.loginDataMetadata = loginDataMetadata
        self.ldfaLogins = ldfaLogins
        self.ldfaMetadata = ldfaMetadata
    }
}

public enum ChromeBridgeRegistry {
    nonisolated(unsafe) public static var current: ChromeBridge?
}
