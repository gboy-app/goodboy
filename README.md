# Flow Engine

Flow Engine moves credentials between password managers on macOS without storing anything itself. Pull from Chrome, KeePassXC, Bitwarden, 1Password, or Proton Pass; push to Chrome, KeePassXC, or a Bitwarden-compatible JSON export. Credentials live in a RAM-only workspace (`SecuredBox`) for the duration of each flow and are cleared when the process exits.

This repository ships the runtime plus `goodboy-mcp`, a stdio [Model Context Protocol](https://modelcontextprotocol.io) server that exposes Flow Engine to MCP clients (Claude Code, Claude Desktop, Cursor, and others).

Flow Engine is the open-source core of [Goodboy](https://goodboy.app). iCloud integration and Apple Credential Exchange Protocol (CXP) support live in the Goodboy macOS app, not here.

## Build

```bash
swift build -c release --product goodboy-mcp
codesign --force --sign "Apple Development" .build/release/goodboy-mcp
```

Why codesign? Keychain entries are namespaced by the binary's signing identity. `swift build` produces an ad-hoc signature whose identity changes on every rebuild, re-prompting for every keychain item. Re-signing with a stable developer identity makes the first "Always Allow" grant persist across rebuilds.

## Quick example — Chrome to JSON

Register `goodboy-mcp` with Claude Code:

```bash
claude mcp add-json goodboy '{"command": "/absolute/path/to/.build/release/goodboy-mcp"}'
```

Open a new session in any directory and ask:

> Pull my Chrome passwords and export them to `~/Downloads/export.json`.

Flow Engine auto-discovers Chrome on first run, so the model picks the existing `chrome-default` device, creates a JSON export device at the path you asked for, and runs a source → destination flow. The `FlowEvent` stream narrates each step:

```
started                       flowId=C80AC61A-…
stepComplete chrome-default   Loaded 15 passwords from Chrome profile "Default"
stepComplete json-default     Exported 15 credentials to Bitwarden JSON
complete
```

The file is written with mode `0600`, uses the Bitwarden JSON schema (importable by almost any password manager), and `SecuredBox` is cleared when the flow ends.

See [mcp.md](mcp.md) for the full tool reference and setup snippets for Cursor, Cline, Continue, Windsurf, Zed, Warp, VS Code, and Gemini CLI.

## What's in the repo

- **`FlowEngine`** — the runtime. `Tool` protocol, `FlowEngine`, `SecuredBox`, `DeviceService`, `SchemaResolver`, AppDB (SQLite via GRDB), macOS Keychain wrapper.
- **`EngineMCP`** — transport-agnostic MCP tool definitions and handlers.
- **`EngineTools`** — connectors: Chrome, KeePassXC CLI, Bitwarden CLI, 1Password CLI, Proton Pass CLI, JSON Export.
- **`goodboy-mcp`** — the stdio MCP executable.

## Tools

| ID | Name | Read | Write | Types |
|---|---|---|---|---|
| `chrome` | Chrome | yes | yes (direct mode) | password |
| `keepasscli` | KeePassXC CLI | yes | yes | password, OTP, passkey |
| `bitwarden` | Bitwarden CLI | yes | — | password, OTP |
| `onepassword` | 1Password CLI | yes | — | password, OTP |
| `protonpass` | Proton Pass CLI | yes | — | password, OTP |
| `json` | JSON Export | — | yes | password, OTP, passkey |

CLI-backed tools require the vendor binary on `PATH`: `keepassxc-cli`, `bw`, `op`, `pass-cli`. Chrome needs no extra tooling — Flow Engine reads and writes the Chrome vault directly.

## Requirements

- macOS 26 (Tahoe) or later
- Swift 6.2 toolchain
- Apple Developer certificate for stable codesigning (optional, but needed for persistent keychain grants)

## Architecture at a glance

```
MCP client (Claude Code / Cursor / …)
       │ stdio
  goodboy-mcp            ← EngineMCP (tool dispatch)
       │
  FlowEngine             ← owns execution
       │
  SecuredBox             ← RAM-only credential hub
       │
  Tools               ← stateless connectors
       │
  macOS Keychain         ← operational params (browser keys, DB passwords)
  SQLite (AppDB)         ← settings, devices, logs
```

- `FlowEngine` owns execution. `run(sourceId)` pulls into `SecuredBox`; `run(sourceId, destId)` does a full source → destination flow. Concurrent flows are blocked.
- `SecuredBox` is RAM-only. Sources `append()`, destinations read. Never written to disk.
- Tools are stateless. All credential data flows through `SecuredBox`.
- The macOS Keychain stores operational parameters (master passwords, browser Safe Storage keys), never the user's credentials.
- AppDB is SQLite (via GRDB) for settings, device configurations, and logs.

## Tests

```bash
swift test
```

## Security

See [SECURITY.md](SECURITY.md) for the full security model, subprocess hardening, and disclosure process.

## License

MIT — see [LICENSE](LICENSE).
