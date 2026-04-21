// goodboy-mcp
//
// Stdio transport for the Goodboy MCP server. Thin process-lifetime
// bootstrap: redirects stdout so registry noise can't corrupt the
// JSON-RPC protocol, registers tools, then hands off to the
// transport-agnostic handlers library.

import Foundation
import MCP
import FlowEngine
import EngineTools
import EngineMCP

@main
struct GoodboyMCP {
    static func main() async throws {
        // Ignore SIGPIPE — Claude Code / Cline / Continue sometimes close
        // stdin abruptly on child-process teardown. Default disposition is
        // terminate; we want EPIPE from write() instead so the transport
        // can shut down cleanly.
        signal(SIGPIPE, SIG_IGN)

        // Reap any XML import tempfiles left over from a crashed run.
        // Cheap, synchronous — belts-and-suspenders to importXML's defer.
        KeePassCLI.sweepOrphanImportFiles()

        let savedStdout = dup(STDOUT_FILENO)
        dup2(STDERR_FILENO, STDOUT_FILENO)

        await MainActor.run { startup() }

        dup2(savedStdout, STDOUT_FILENO)
        close(savedStdout)

        let server = Server(
            name: "goodboy-stdio",
            version: "1.0.0",
            capabilities: .init(tools: .init(listChanged: false))
        )

        await server.withMethodHandler(ListTools.self) { _ in
            ListTools.Result(tools: allTools)
        }

        await server.withMethodHandler(CallTool.self) { params in
            try await handleToolCall(params)
        }

        let transport = StdioTransport()
        try await server.start(transport: transport)
        await server.waitUntilCompleted()
    }

    @MainActor
    private static func startup() {
        // STDIO MCP: only the engine's built-in tools. Any tool id not
        // registered surfaces a "tool not registered" error through the
        // registry (e.g. if a caller tries a device id from another host
        // with a richer registration).
        ToolRegistry.shared.registerBundled(engineTools())
        registerChromeBridge()
        DeviceService.shared.bootstrapDefaults()
    }
}
