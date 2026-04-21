import Foundation
import EngineMCP

/// Register the Chrome bridge backing so MCP handlers can reach ChromeHelper
/// without EngineMCP depending on the full tool library. Called
/// at startup by both the SwiftUI app (Mode 1) and `goodboy-mcp` (Mode 2).
public func registerChromeBridge() {
    ChromeBridgeRegistry.current = ChromeHelperBridge()
}

private struct ChromeHelperBridge: ChromeBridge {
    var isInstalled: Bool { ChromeHelper.isChromeInstalled() }
    var isRunning: Bool { ChromeHelper.isChromeRunning() }

    func listProfiles() throws -> [ChromeProfileRow] {
        try ChromeHelper.listProfiles().map { p in
            let syncMode = ChromeHelper.detectSyncMode(folder: p.folder)
            let stats = ChromeHelper.profileStats(folder: p.folder)
            let recommended: Bool
            switch syncMode {
            case .accountStorage, .both: recommended = true
            case .chromeSync, .empty: recommended = false
            }
            return ChromeProfileRow(
                folder: p.folder,
                name: p.name,
                email: p.email ?? "",
                syncMode: syncMode.rawValue,
                recommended: recommended,
                loginDataLogins: stats.loginDataLogins,
                loginDataMetadata: stats.loginDataMetadata,
                ldfaLogins: stats.ldfaLogins,
                ldfaMetadata: stats.ldfaMetadata
            )
        }
    }

    func extractBrowserKey(chromeDir: String) throws -> String {
        try ChromeHelper.extractBrowserKey(chromeDir: chromeDir)
    }
}
