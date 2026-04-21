// MCP handlers for the Chrome profile tools. All calls go through
// `ChromeBridgeRegistry.current` — nil in the standalone binary, which
// returns a "install the app" error instead of linking Pro code.

import Foundation
import MCP

func handleChromeProfiles() -> CallTool.Result {
    guard let bridge = ChromeBridgeRegistry.current else {
        return proOnlyResult(feature: "Chrome profile discovery")
    }
    guard bridge.isInstalled else {
        return CallTool.Result(content: [mcpText(jsonString(["error": "Chrome not installed"]))], isError: true)
    }
    do {
        let profiles = try bridge.listProfiles()
        let items: [[String: Any]] = profiles.map { p in
            [
                "folder": p.folder,
                "name": p.name,
                "email": p.email,
                "syncMode": p.syncMode,
                "recommended": p.recommended,
                "loginData": [
                    "logins": p.loginDataLogins,
                    "metadata": p.loginDataMetadata,
                ] as [String: Any],
                "ldfa": [
                    "logins": p.ldfaLogins,
                    "metadata": p.ldfaMetadata,
                ] as [String: Any],
            ]
        }
        return CallTool.Result(content: [mcpText(jsonString(["count": items.count, "profiles": items]))])
    } catch {
        return CallTool.Result(content: [mcpText(jsonString(["error": error.localizedDescription]))], isError: true)
    }
}

func handleChromeStatus() -> CallTool.Result {
    guard let bridge = ChromeBridgeRegistry.current else {
        return proOnlyResult(feature: "Chrome status")
    }
    let result: [String: Any] = [
        "installed": bridge.isInstalled,
        "running": bridge.isRunning,
    ]
    return CallTool.Result(content: [mcpText(jsonString(result))])
}

func proOnlyResult(feature: String) -> CallTool.Result {
    let msg = "\(feature) is not available in this build. "
        + "Install the Goodboy app from https://goodboy.app for Chrome and iCloud integration."
    return CallTool.Result(content: [mcpText(jsonString(["error": msg]))], isError: true)
}
