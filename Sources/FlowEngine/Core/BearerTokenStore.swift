// First launch: mint a 256-bit bearer token + pick a free high TCP
// port on 127.0.0.1, persist both to AppPaths.mcpToken (0600, race-
// free via O_CREAT|O_EXCL). Subsequent launches read and reuse.
// Port collision → reroll and rewrite.
//
// Invariant 2 — dies with the app. Invariant 6 — token only ever
// sits in a 0600 file inside a 0700 directory.

import Foundation
import Security
import os.log

public enum BearerTokenStoreError: Error {
    case tokenGenerationFailed
    case portAllocationFailed
    case persistFailed(String)
    case corruptFile
}

public struct MCPCredentials: Codable, Sendable {
    public let token: String   // base64 URL-safe
    public let port: UInt16

    public init(token: String, port: UInt16) {
        self.token = token
        self.port = port
    }
}

public enum BearerTokenStore {

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "BearerTokenStore")

    /// Read existing credentials without side effects. No bind probe,
    /// no reroll, no write. Use this from read-only call sites (the
    /// Settings → MCP panel, install-snippet renderers, anything that
    /// just wants to know "what port/token is the running server on").
    ///
    /// `loadOrMint` is reserved for the single place that actually
    /// binds the listener — `InAppMCPServer.start()`. Calling it from
    /// a read-only path will reroll the port mid-session, because
    /// `portIsBindable` does a plain `bind()` (no `SO_REUSEADDR`)
    /// against a port the app's own NWListener already owns — that
    /// bind fails, the reroll branch fires, the file gets a fresh
    /// port, and the Settings-displayed port drifts away from the
    /// actual listener.
    public static func read() throws -> MCPCredentials {
        try readFile()
    }

    /// Load existing credentials, or mint+persist new ones on first
    /// launch. If the stored port fails to bind (collision), roll a
    /// fresh port, rewrite, return the updated tuple.
    ///
    /// **Call exactly once per process**, from the code path that will
    /// immediately bind the listener. Read-only callers use `read()`.
    public static func loadOrMint() throws -> MCPCredentials {
        if let existing = try? readFile() {
            if portIsBindable(existing.port) {
                return existing
            }
            log.info("stored port \(existing.port, privacy: .public) unavailable; rerolling")
            let rerolled = MCPCredentials(token: existing.token, port: try freePort())
            try writeFile(rerolled)
            return rerolled
        }

        let minted = MCPCredentials(token: try randomToken(), port: try freePort())
        try writeFile(minted)
        return minted
    }

    // MARK: - Token

    private static func randomToken() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw BearerTokenStoreError.tokenGenerationFailed
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - Port

    /// Bind a TCP socket to 127.0.0.1:0, let the kernel pick a free
    /// ephemeral port, read it back, close. The returned port is free
    /// at the moment of return; an adversary could race, which is why
    /// InAppMCPServer handles EADDRINUSE with a reroll.
    private static func freePort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BearerTokenStoreError.portAllocationFailed }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0

        let bindRet = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRet == 0 else { throw BearerTokenStoreError.portAllocationFailed }

        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRet = withUnsafeMutablePointer(to: &bound) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(fd, sa, &len)
            }
        }
        guard nameRet == 0 else { throw BearerTokenStoreError.portAllocationFailed }

        return UInt16(bigEndian: bound.sin_port)
    }

    private static func portIsBindable(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = port.bigEndian

        let ret = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return ret == 0
    }

    // MARK: - File I/O

    private static func readFile() throws -> MCPCredentials {
        let data = try Data(contentsOf: AppPaths.mcpToken)
        return try JSONDecoder().decode(MCPCredentials.self, from: data)
    }

    /// Write via open(O_CREAT|O_EXCL|O_WRONLY, 0600) — no chmod-after-
    /// write race. If the file already exists (rewrite path), remove
    /// first then create fresh.
    private static func writeFile(_ creds: MCPCredentials) throws {
        let path = AppPaths.mcpToken.path
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(creds)

        _ = unlink(path)
        let fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard fd >= 0 else {
            throw BearerTokenStoreError.persistFailed("open: \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }

        let written = data.withUnsafeBytes { raw -> ssize_t in
            guard let base = raw.baseAddress else { return -1 }
            return write(fd, base, raw.count)
        }
        guard written == data.count else {
            throw BearerTokenStoreError.persistFailed("write: short write")
        }
    }
}
