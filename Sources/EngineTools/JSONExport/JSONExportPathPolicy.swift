// Path whitelist enforced by JSONExportTool.check() and by .execute()
// before the write. Closes M6 (path escape via prompt injection) +
// L8 (file perms on the emitted artifact).
//
// Policy:
//    1. Tilde-expanded, standardized, symlink-resolved.
//    2. Must be inside ~/Downloads, ~/Documents, or ~/Desktop.
//    3. No path component equal to `..`.
//    4. No basename starting with `.`.
//    5. Must end in `.json`.

import Foundation
import FlowEngine

enum JSONExportPathPolicy {

    /// Resolve a user-provided path: expand `~`, standardize (collapse
    /// `./`, `../`), and resolve symlinks. `check()` and `execute()`
    /// both operate on the resolved form so the string used in one is
    /// the string used in the other.
    static func resolve(_ path: String) -> String {
        let expanded = (path as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: expanded).standardizedFileURL.resolvingSymlinksInPath()
        return url.path
    }

    /// Return `nil` if the path is acceptable; otherwise a DeviceError
    /// whose message names the rule that was violated.
    static func validate(_ path: String) -> DeviceError? {
        let resolved = resolve(path)
        let url = URL(fileURLWithPath: resolved)

        // Rule 3 — no `..` components (after standardization this is
        // only possible if symlink resolution bounced us upward, which
        // we also treat as a reject).
        if url.pathComponents.contains("..") {
            return DeviceError(
                category: .missingParam,
                message: "Export path must not contain '..'. Choose a concrete location inside Downloads, Documents, or Desktop.",
                action: "Select path"
            )
        }

        // Rule 4 — basename must not start with `.`
        let basename = url.lastPathComponent
        if basename.hasPrefix(".") {
            return DeviceError(
                category: .missingParam,
                message: "Export filename must not start with '.'.",
                action: "Rename file"
            )
        }

        // Rule 5 — `.json` suffix
        if url.pathExtension.lowercased() != "json" {
            return DeviceError(
                category: .missingParam,
                message: "Export filename must end in '.json'.",
                action: "Rename file"
            )
        }

        // Rule 2 — under one of the allowed roots.
        let inAllowed = allowedRoots().contains { resolved == $0 || resolved.hasPrefix($0 + "/") }
        if !inAllowed {
            return DeviceError(
                category: .missingParam,
                message: "Export path must be inside ~/Downloads, ~/Documents, or ~/Desktop.",
                action: "Select path"
            )
        }

        return nil
    }

    /// Production whitelist: ~/Downloads, ~/Documents, ~/Desktop.
    /// In DEBUG builds, `GOODBOY_TEST_EXPORT_ROOT` can add one extra
    /// absolute path — used by tests to write into a tmp dir without
    /// touching the user's real Downloads.
    private static func allowedRoots() -> [String] {
        let home = NSHomeDirectory()
        var roots: [String] = [
            URL(fileURLWithPath: home).appendingPathComponent("Downloads").standardizedFileURL.resolvingSymlinksInPath().path,
            URL(fileURLWithPath: home).appendingPathComponent("Documents").standardizedFileURL.resolvingSymlinksInPath().path,
            URL(fileURLWithPath: home).appendingPathComponent("Desktop").standardizedFileURL.resolvingSymlinksInPath().path,
        ]
        #if DEBUG
        if let extra = ProcessInfo.processInfo.environment["GOODBOY_TEST_EXPORT_ROOT"] {
            let resolved = URL(fileURLWithPath: extra).standardizedFileURL.resolvingSymlinksInPath().path
            roots.append(resolved)
        }
        #endif
        return roots
    }
}
