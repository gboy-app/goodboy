// Single source of truth for the app's storage paths.
//
// App storage:  ~/Library/Application Support/Goodboy/  (override: GOODBOY_STORAGE_PATH)

import Foundation

public enum AppPaths {

    /// Root directory for all app storage. Created with `0700` on
    /// first access so any secret-bearing file we drop in later
    /// (mcp.token, goodboy.db, devices/*) inherits a directory only
    /// the owning user can traverse. chmod is idempotent — cheap
    /// re-apply covers pre-existing dirs created under a looser umask.
    public static let base: URL = {
        let url: URL
        if let envPath = ProcessInfo.processInfo.environment["GOODBOY_STORAGE_PATH"] {
            url = URL(fileURLWithPath: envPath, isDirectory: true)
        } else {
            url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Goodboy", isDirectory: true)
        }
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: url.path
        )
        return url
    }()

    /// ~/Storage/mcp.token — bearer token + port for the in-app MCP
    /// server. 0600, next to the other per-user artifacts.
    public static let mcpToken: URL = base.appendingPathComponent("mcp.token")

    /// ~/Storage/Devices/
    public static let devices: URL = {
        let url = base.appendingPathComponent("Devices", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    /// ~/Storage/Tools/  (external tool plugins)
    public static let externalTools: URL = {
        let url = base.appendingPathComponent("Tools", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

}
