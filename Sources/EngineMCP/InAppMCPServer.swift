// Mode 1 transport: an HTTP/JSON-RPC MCP server that lives inside
// the SwiftUI process and binds 127.0.0.1 only. Shares memory with
// the UI — same SecuredBox.shared, same ToolRegistry, same
// DeviceService — so flows fired from Claude Code / Claude Desktop
// land live in the app's data grid.
//
// Authentication: bearer-token only. Any process running as the
// user that can read AppPaths.mcpToken (0600) can connect. Code-
// signing-based peer-auth is deferred to post-website (see plan
// §5.D4-clients); at that point this file grows a second gate in
// `authorize(_:)`.
//
// Invariant 1 — never persist request/response bodies.
// Invariant 2 — dies with the app (NWListener cancel on stop()).

import Foundation
import Network
import os.log
import MCP
import FlowEngine

public final class InAppMCPServer: @unchecked Sendable {

    public static let shared = InAppMCPServer()

    private static let log = Logger(subsystem: "app.gboy.goodboy", category: "InAppMCPServer")

    private struct State {
        var listener: NWListener?
        var server: Server?
        var transport: StatelessHTTPServerTransport?
        var expectedToken: String?
        /// Cached `result` payload (raw JSON bytes) from the first successful
        /// initialize response. Used to replay initialize responses for
        /// subsequent calls, since the SDK's `Server` rejects re-initialization
        /// with "Server is already initialized". See dispatch() for details.
        var cachedInitializeResult: Data?
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    private let queue = DispatchQueue(label: "app.gboy.goodboy.mcpserver")

    private init() {}

    // MARK: - Lifecycle

    /// Mint (or reuse) credentials, start the MCP server, bind the
    /// TCP listener. Idempotent: a second call no-ops.
    public func start() async {
        let alreadyRunning = state.withLock { $0.listener != nil }
        guard !alreadyRunning else { return }

        let creds: MCPCredentials
        do {
            creds = try BearerTokenStore.loadOrMint()
        } catch {
            Self.log.error("BearerTokenStore failed: \(error.localizedDescription, privacy: .public)")
            return
        }

        let server = Server(
            name: "goodboy",
            version: "1.0.0",
            capabilities: .init(tools: .init(listChanged: false))
        )
        let transport = StatelessHTTPServerTransport()

        await server.withMethodHandler(ListTools.self) { _ in
            ListTools.Result(tools: allTools)
        }
        await server.withMethodHandler(CallTool.self) { params in
            MCPActivityLog.shared.append("\(params.name)")
            // D.5 — tag every in-app invocation so handlers (specifically
            // `goodboy_run`) can route through the Mode 1 approval gate.
            return try await MCPInvokerContext.$current.withValue(.inAppMCP) {
                try await handleToolCall(params)
            }
        }

        do {
            try await server.start(transport: transport)
        } catch {
            Self.log.error("MCP server start failed: \(error.localizedDescription, privacy: .public)")
            return
        }

        state.withLock {
            $0.expectedToken = creds.token
            $0.server = server
            $0.transport = transport
        }

        do {
            try bindListener(port: creds.port)
        } catch {
            Self.log.error("NWListener bind failed: \(error.localizedDescription, privacy: .public)")
            if let rerolled = try? BearerTokenStore.loadOrMint() {
                state.withLock { $0.expectedToken = rerolled.token }
                do {
                    try bindListener(port: rerolled.port)
                } catch {
                    Self.log.error("NWListener bind retry failed: \(error.localizedDescription, privacy: .public)")
                }
            }
        }
    }

    public func stop() {
        let (l, s) = state.withLock { s -> (NWListener?, Server?) in
            let l = s.listener
            let srv = s.server
            s.listener = nil
            s.server = nil
            s.transport = nil
            return (l, srv)
        }
        l?.cancel()
        if let s {
            Task { await s.stop() }
        }
    }

    // MARK: - TCP listener

    private func bindListener(port: UInt16) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw NSError(domain: "InAppMCPServer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid port"])
        }
        let params = NWParameters.tcp
        if let tcp = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            tcp.version = .v4
        }
        params.acceptLocalOnly = true
        params.allowLocalEndpointReuse = true

        let newListener = try NWListener(using: params, on: nwPort)
        newListener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        newListener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                Self.log.info("InAppMCPServer listening on 127.0.0.1:\(port, privacy: .public)")
            case .failed(let err):
                Self.log.error("NWListener failed: \(err.localizedDescription, privacy: .public)")
            default:
                break
            }
        }
        newListener.start(queue: queue)
        state.withLock { $0.listener = newListener }
    }

    // MARK: - Connection handling

    private func accept(_ connection: NWConnection) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.readRequest(on: connection, accumulated: Data())
            case .failed, .cancelled:
                connection.cancel()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// Read until we have a full HTTP request (headers + body-by-
    /// Content-Length). Simple state machine — fine for the small,
    /// trusted request volume Mode 1 sees.
    private func readRequest(on connection: NWConnection, accumulated: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] chunk, _, isComplete, error in
            guard let self else { return }
            var buffer = accumulated
            if let chunk { buffer.append(chunk) }

            if error != nil {
                connection.cancel()
                return
            }
            if isComplete && chunk == nil && buffer.isEmpty {
                connection.cancel()
                return
            }

            guard let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else {
                if buffer.count > 256 * 1024 {
                    self.respond(connection, status: 413, body: nil, close: true)
                    return
                }
                self.readRequest(on: connection, accumulated: buffer)
                return
            }

            let headerBlock = buffer.subdata(in: 0..<headerEnd.lowerBound)
            guard let headerText = String(data: headerBlock, encoding: .utf8) else {
                self.respond(connection, status: 400, body: nil, close: true)
                return
            }
            let parsed = self.parseHeaders(headerText)
            let contentLength = Int(parsed.headers["content-length"] ?? "0") ?? 0
            let bodyStart = headerEnd.upperBound
            let bodyBytesHave = buffer.count - bodyStart

            if bodyBytesHave < contentLength {
                self.readRequest(on: connection, accumulated: buffer)
                return
            }
            let body = contentLength > 0
                ? buffer.subdata(in: bodyStart..<(bodyStart + contentLength))
                : nil

            self.dispatch(connection: connection, method: parsed.method, path: parsed.path, headers: parsed.headers, body: body)
        }
    }

    private struct ParsedHead {
        let method: String
        let path: String
        let headers: [String: String]
    }

    private func parseHeaders(_ text: String) -> ParsedHead {
        var lines = text.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return ParsedHead(method: "", path: "", headers: [:]) }
        let requestLine = lines.removeFirst().split(separator: " ", maxSplits: 2).map(String.init)
        let method = requestLine.first ?? ""
        let path = requestLine.count > 1 ? requestLine[1] : "/"
        var headers: [String: String] = [:]
        for line in lines where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }
        return ParsedHead(method: method, path: path, headers: headers)
    }

    // MARK: - Dispatch

    private func dispatch(
        connection: NWConnection,
        method: String,
        path: String,
        headers: [String: String],
        body: Data?
    ) {
        // Origin — MCP Streamable HTTP spec mandates 403 if present and
        // not loopback. Absence is allowed (CLI clients like Claude Code
        // send no Origin). Electron shells (Claude Desktop) send "null"
        // on file:// or localhost — that whitelist entry is load-bearing.
        if let origin = headers["origin"] {
            let ok = origin.hasPrefix("http://127.0.0.1")
                  || origin.hasPrefix("http://localhost")
                  || origin == "null"
            guard ok else {
                Self.log.info("rejected: cross-origin (\(origin, privacy: .public))")
                self.respond(connection, status: 403, body: nil, close: true)
                return
            }
        }

        // Host — defense-in-depth against DNS-rebinding (CVE-2025-49596
        // class). acceptLocalOnly binds to loopback, but an attacker page
        // resolving attacker.com → 127.0.0.1 can smuggle a non-loopback
        // Host header past the bind. Reject anything that isn't our
        // expected name:port.
        if let host = headers["host"] {
            let expectedPort = state.withLock { $0.listener?.port?.rawValue }
            let ok = ["127.0.0.1", "localhost"].contains { name in
                host == name || (expectedPort.map { host == "\(name):\($0)" } ?? false)
            }
            guard ok else {
                Self.log.info("rejected: bad Host (\(host, privacy: .public))")
                self.respond(connection, status: 403, body: nil, close: true)
                return
            }
        }

        guard authorizeBearer(headers: headers) else {
            Self.log.info("rejected: missing or bad bearer")
            self.respond(connection, status: 401, body: nil, close: true)
            return
        }

        let transport = state.withLock { $0.transport }
        guard let transport else {
            self.respond(connection, status: 503, body: nil, close: true)
            return
        }

        // Strip Origin before handing to the SDK: the app-level gate above
        // already enforced the loopback policy (and accepts "null" for
        // Electron clients like Claude Desktop), while the SDK's default
        // OriginValidator is stricter and rejects "null" outright.
        var sdkHeaders: [String: String] = [:]
        for (k, v) in headers where k != "origin" {
            sdkHeaders[canonicalHeaderName(k)] = v
        }

        // Intercept repeat `initialize` calls. The SDK's `Server` actor flips
        // a private `isInitialized` flag on the first successful initialize,
        // and any subsequent initialize returns `-32600 "Server is already
        // initialized"` — which breaks Electron clients and `claude mcp list`
        // health probes. We cache the `result` from the first response and
        // replay it for later calls, leaving tool calls untouched.
        let parsedInitId = parseInitializeRequestID(body: body)
        if let rpcId = parsedInitId,
           let cached = state.withLock({ $0.cachedInitializeResult }) {
            writeReplayedInitializeResponse(connection: connection, rpcId: rpcId, cachedResult: cached)
            return
        }

        let request = HTTPRequest(
            method: method,
            headers: sdkHeaders,
            body: body,
            path: path
        )

        Task { [weak self] in
            let response = await transport.handleRequest(request)
            if parsedInitId != nil {
                self?.cacheInitializeResultIfSuccess(response: response)
            }
            self?.writeResponse(connection: connection, response: response)
        }
    }

    /// If the request body is a JSON-RPC `initialize`, return its `id` as
    /// raw JSON bytes (e.g. `"42"`, `42`, `"abc"`). `nil` for any other
    /// method, a notification, or an unparseable body.
    private func parseInitializeRequestID(body: Data?) -> Data? {
        guard let body else { return nil }
        guard let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return nil
        }
        guard (obj["method"] as? String) == "initialize" else { return nil }
        guard let id = obj["id"] else { return nil }
        return try? JSONSerialization.data(withJSONObject: id, options: [.fragmentsAllowed])
    }

    /// Cache the `result` field of a successful initialize response so we
    /// can replay it on subsequent initialize calls.
    private func cacheInitializeResultIfSuccess(response: HTTPResponse) {
        guard response.statusCode == 200, let data = response.bodyData else { return }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        guard let result = obj["result"] else { return }
        guard let resultData = try? JSONSerialization.data(withJSONObject: result, options: [.fragmentsAllowed]) else {
            return
        }
        state.withLock { $0.cachedInitializeResult = resultData }
    }

    /// Synthesize a JSON-RPC initialize response using the cached `result`
    /// and the current request's `id`.
    private func writeReplayedInitializeResponse(connection: NWConnection, rpcId: Data, cachedResult: Data) {
        var body = Data(#"{"jsonrpc":"2.0","id":"#.utf8)
        body.append(rpcId)
        body.append(Data(#","result":"#.utf8))
        body.append(cachedResult)
        body.append(Data("}".utf8))

        var out = "HTTP/1.1 200 OK\r\n"
        out += "Content-Type: application/json\r\n"
        out += "Content-Length: \(body.count)\r\n"
        out += "Connection: close\r\n"
        out += "\r\n"
        var data = Data(out.utf8)
        data.append(body)
        connection.send(content: data, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func authorizeBearer(headers: [String: String]) -> Bool {
        let expected = state.withLock { $0.expectedToken }
        guard let expected else { return false }
        guard let auth = headers["authorization"] else { return false }
        let presented: String
        if auth.lowercased().hasPrefix("bearer ") {
            presented = String(auth.dropFirst("bearer ".count))
        } else {
            presented = auth
        }
        return constantTimeEquals(presented, expected)
    }

    private func canonicalHeaderName(_ lower: String) -> String {
        switch lower {
        case "authorization": return "Authorization"
        case "content-type": return "Content-Type"
        case "content-length": return "Content-Length"
        case "accept": return "Accept"
        case "origin": return "Origin"
        case "host": return "Host"
        case "mcp-session-id": return "MCP-Session-Id"
        case "mcp-protocol-version": return "MCP-Protocol-Version"
        default: return lower
        }
    }

    // MARK: - Response

    private func writeResponse(connection: NWConnection, response: HTTPResponse) {
        if case .stream(let stream, let headers) = response {
            writeStream(connection: connection, stream: stream, headers: headers)
            return
        }

        var out = "HTTP/1.1 \(response.statusCode) \(reason(response.statusCode))\r\n"
        var headers = response.headers
        let body = response.bodyData
        let len = body?.count ?? 0
        headers["Content-Length"] = String(len)
        headers["Connection"] = "close"
        for (k, v) in headers {
            out += "\(k): \(v)\r\n"
        }
        out += "\r\n"
        var data = Data(out.utf8)
        if let body { data.append(body) }
        connection.send(content: data, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func writeStream(
        connection: NWConnection,
        stream: AsyncThrowingStream<Data, Swift.Error>,
        headers: [String: String]
    ) {
        var out = "HTTP/1.1 200 OK\r\n"
        var h = headers
        h["Transfer-Encoding"] = "chunked"
        h["Content-Type"] = h["Content-Type"] ?? "text/event-stream"
        h["Cache-Control"] = "no-cache"
        h["Connection"] = "close"
        for (k, v) in h { out += "\(k): \(v)\r\n" }
        out += "\r\n"
        connection.send(content: Data(out.utf8), completion: .contentProcessed { _ in })

        Task.detached {
            do {
                for try await chunk in stream {
                    let header = String(format: "%X\r\n", chunk.count)
                    var frame = Data(header.utf8)
                    frame.append(chunk)
                    frame.append(Data("\r\n".utf8))
                    await InAppMCPServer.sendAsync(connection, data: frame)
                }
                await InAppMCPServer.sendAsync(connection, data: Data("0\r\n\r\n".utf8))
            } catch {}
            connection.cancel()
        }
    }

    private static func sendAsync(_ connection: NWConnection, data: Data) async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            connection.send(content: data, completion: .contentProcessed { _ in cont.resume() })
        }
    }

    private func respond(_ connection: NWConnection, status: Int, body: Data?, close: Bool) {
        var out = "HTTP/1.1 \(status) \(reason(status))\r\n"
        out += "Content-Length: \(body?.count ?? 0)\r\n"
        if close { out += "Connection: close\r\n" }
        out += "\r\n"
        var data = Data(out.utf8)
        if let body { data.append(body) }
        connection.send(content: data, completion: .contentProcessed { _ in
            if close { connection.cancel() }
        })
    }

    private func reason(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 202: return "Accepted"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 413: return "Payload Too Large"
        case 500: return "Internal Server Error"
        case 503: return "Service Unavailable"
        default: return "OK"
        }
    }

    // MARK: - Utility

    private func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let aBytes = Array(a.utf8)
        let bBytes = Array(b.utf8)
        guard aBytes.count == bBytes.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<aBytes.count {
            diff |= aBytes[i] ^ bBytes[i]
        }
        return diff == 0
    }
}
