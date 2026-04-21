// Shared subprocess utility for CLI-based tools.
// Extracted from KeePassCLI.swift to avoid duplication across Bitwarden, 1Password, ProtonPass.

import Foundation
import os.log
import FlowEngine

public final class CLIRunner: Sendable {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "CLIRunner")

    // MARK: - Team-ID verification cache
    //
    // `verifyTeamID` ran on every `findBinary()` call — and `findBinary()`
    // runs once per CLI operation, so a single pull would shell out to
    // codesign dozens of times and flood the log with the same mismatch
    // line. Cache the result per (tool, path) for the process lifetime;
    // the binary on disk doesn't change mid-process.
    private static let teamIdCacheLock = NSLock()
    nonisolated(unsafe) private static var teamIdCache: [String: Bool] = [:]

    // MARK: - Find Binary

    /// Find a CLI binary. Checks: env override → standard paths → `which`.
    /// If `expectedTeamIds` is provided, a Team-ID mismatch logs a
    /// warning at `default` level (M12 warn-only) but does not reject.
    public static func findBinary(
        envKey: String,
        standardPaths: [String],
        whichName: String,
        expectedTeamIds: [String] = []
    ) -> String? {
        if let resolved = resolveBinary(envKey: envKey, standardPaths: standardPaths, whichName: whichName) {
            if !expectedTeamIds.isEmpty {
                verifyTeamID(tool: whichName, path: resolved, expected: expectedTeamIds)
            }
            return resolved
        }
        return nil
    }

    private static func resolveBinary(envKey: String, standardPaths: [String], whichName: String) -> String? {
        if let override = ProcessInfo.processInfo.environment[envKey] {
            if FileManager.default.isExecutableFile(atPath: override) {
                return override
            }
            return nil
        }

        let localBin = NSString(string: "~/.local/bin/\(whichName)").expandingTildeInPath
        for path in standardPaths + [localBin] {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }

        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = [whichName]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                if !path.isEmpty { return path }
            }
        } catch {}

        return nil
    }

    /// M12 (warn-only): verify the resolved binary is signed by one of
    /// the expected Team IDs. Mismatches log but do not reject — we
    /// need dogfooding data before flipping to hard rejection.
    ///
    /// Cached per (tool, path) for the process lifetime: the binary on
    /// disk is stable, and re-running `codesign --verify` on every
    /// `findBinary()` call wallpapers the log with the same mismatch.
    private static func verifyTeamID(tool: String, path: String, expected: [String]) {
        let cacheKey = "\(tool)|\(path)|\(expected.joined(separator: ","))"
        teamIdCacheLock.lock()
        let cached = teamIdCache[cacheKey]
        teamIdCacheLock.unlock()
        if cached != nil { return }

        let reqs = expected.map { teamId in
            "(anchor apple generic and certificate leaf[subject.OU] = \"\(teamId)\")"
        }.joined(separator: " or ")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["--verify", "--verbose", "-R=\(reqs)", path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        var matched = false
        do {
            try process.run()
            process.waitUntilExit()
            matched = (process.terminationStatus == 0)
            if !matched {
                log.notice("cli-resolution mismatch: tool=\(tool, privacy: .public) path=\(path, privacy: .public) match=false expected=\(expected.joined(separator: ","), privacy: .public)")
            }
        } catch {
            // codesign itself failed to run — not actionable, don't block.
            // Don't cache: a transient failure shouldn't suppress the
            // next attempt's verification.
            return
        }

        teamIdCacheLock.lock()
        teamIdCache[cacheKey] = matched
        teamIdCacheLock.unlock()
    }

    // MARK: - Run

    /// Run a CLI command. Password/input via stdin pipe. Drains stdout/stderr
    /// on background threads to prevent pipe-buffer deadlock (same pattern as KeePassCLI.run).
    /// `environment` merges with inherited env (for BW_SESSION, OP_SERVICE_ACCOUNT_TOKEN, etc.).
    /// Returns (stdout, stderr, exitCode).
    public static func run(
        binary: String,
        arguments: [String],
        environment: [String: String] = [:],
        stdinString: String? = nil,
        timeout: TimeInterval = 30
    ) throws -> (stdout: String, stderr: String, exitCode: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = arguments

        // M10: build env from scratch. Never inherit the parent's
        // entire environment — it can carry unrelated secrets from
        // other apps (including anything the app was launched with),
        // and it's a wide surface. Explicit PATH + a minimal
        // passthrough set + caller overrides.
        process.environment = buildChildEnvironment(overrides: environment)

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        // Pipe input via stdin
        if let stdinString = stdinString {
            let stdinPipe = Pipe()
            process.standardInput = stdinPipe
            stdinPipe.fileHandleForWriting.write(Data(stdinString.utf8))
            stdinPipe.fileHandleForWriting.closeFile()
        }

        // Drain stdout/stderr on background threads to prevent pipe-buffer deadlock.
        // macOS pipes buffer ~64 KB; if the child fills that before we read, it blocks.
        nonisolated(unsafe) var stdoutData = Data()
        nonisolated(unsafe) var stderrData = Data()
        let group = DispatchGroup()

        group.enter()
        DispatchQueue.global().async {
            stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        try process.run()

        // Wait with timeout
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        if process.isRunning {
            // L5: SIGTERM first, 2s grace, then SIGKILL. A wedged
            // `op signin` or biometrics-prompt-cancelled `bw` can
            // ignore SIGTERM; we escalate so the timeout is honored.
            process.terminate()
            let killDeadline = Date().addingTimeInterval(2.0)
            while process.isRunning && Date() < killDeadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            group.wait()
            throw CLIRunnerError.timedOut(Int(timeout))
        }

        // Process exited — wait for background reads to finish
        group.wait()

        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        var stderr = String(data: stderrData, encoding: .utf8) ?? ""

        // L7: redact the stdin payload (usually a password) and known
        // secret-bearing env values from stderr before it reaches any
        // log or error message a caller might emit.
        stderr = redactSecrets(stderr, stdin: stdinString, env: environment)

        return (stdout, stderr, process.terminationStatus)
    }

    // MARK: - Environment construction (M10)

    /// Minimal environment we hand to every CLI subprocess. Overrides
    /// win — callers add BW_SESSION, OP_SERVICE_ACCOUNT_TOKEN, etc.
    /// `keepassxc-cli` may need `QT_QPA_PLATFORM=minimal` — callers
    /// supply it explicitly (see KeePassCLI call sites).
    private static let passthroughEnvKeys: [String] = [
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "BITWARDENCLI_APPDATA_DIR",
    ]

    private static let pinnedPath = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    private static func buildChildEnvironment(overrides: [String: String]) -> [String: String] {
        var env: [String: String] = [:]
        let parent = ProcessInfo.processInfo.environment
        for key in passthroughEnvKeys {
            if let v = parent[key] { env[key] = v }
        }
        // PATH is pinned; append ~/.local/bin so the in-app installer
        // target is reachable without giving the child the parent's
        // full PATH.
        let localBin = NSString(string: "~/.local/bin").expandingTildeInPath
        env["PATH"] = pinnedPath + ":" + localBin
        for (k, v) in overrides { env[k] = v }
        return env
    }

    private static let knownSecretEnvKeys: Set<String> = [
        "BW_PASSWORD", "BW_CLIENTSECRET", "BW_SESSION",
        "OP_SERVICE_ACCOUNT_TOKEN",
        "PROTON_PASSWORD", "PROTON_TOTP",
    ]

    private static func redactSecrets(_ stderr: String, stdin: String?, env: [String: String]) -> String {
        var out = stderr
        if let stdin, !stdin.isEmpty {
            // Redact each non-blank line of stdin; tools often pipe
            // "<password>\n<secondary>\n" so we redact each token
            // individually.
            for token in stdin.split(separator: "\n") where !token.isEmpty {
                let s = String(token)
                if s.count >= 4 { // avoid stomping every vowel
                    out = out.replacingOccurrences(of: s, with: "<redacted>")
                }
            }
        }
        for (key, value) in env where knownSecretEnvKeys.contains(key) {
            if value.count >= 4 {
                out = out.replacingOccurrences(of: value, with: "<redacted>")
            }
        }
        return out
    }

    // MARK: - Run + JSON Decode

    /// Convenience: run + JSON decode. Throws on non-zero exit or decode failure.
    public static func runJSON<T: Decodable>(
        binary: String,
        arguments: [String],
        environment: [String: String] = [:],
        stdinString: String? = nil,
        as type: T.Type,
        timeout: TimeInterval = 30
    ) throws -> T {
        let result = try run(
            binary: binary,
            arguments: arguments,
            environment: environment,
            stdinString: stdinString,
            timeout: timeout
        )

        guard result.exitCode == 0 else {
            throw CLIRunnerError.nonZeroExit(result.exitCode, result.stderr)
        }

        guard let data = result.stdout.data(using: .utf8) else {
            throw CLIRunnerError.invalidOutput("stdout is not valid UTF-8")
        }

        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw CLIRunnerError.jsonDecodeFailed(error.localizedDescription)
        }
    }
}

// MARK: - Errors

public enum CLIRunnerError: Error, LocalizedError {
    case timedOut(Int)
    case nonZeroExit(Int32, String)
    case invalidOutput(String)
    case jsonDecodeFailed(String)

    public var isTimeout: Bool {
        if case .timedOut = self { return true }
        return false
    }

    public var errorDescription: String? {
        switch self {
        case .timedOut(let seconds):
            return "Command timed out after \(seconds)s"
        case .nonZeroExit(let code, let stderr):
            return "Command failed (exit \(code)): \(stderr)"
        case .invalidOutput(let detail):
            return "Invalid output: \(detail)"
        case .jsonDecodeFailed(let detail):
            return "JSON decode failed: \(detail)"
        }
    }
}
