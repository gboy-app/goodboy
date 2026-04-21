# `goodboy-mcp` — Tool Reference

`goodboy-mcp` is the stdio Model Context Protocol server for Flow Engine. It speaks MCP over stdio and exposes the tool set shipped in this repo: Chrome, KeePassXC, Bitwarden, 1Password, Proton Pass, and JSON Export.

This binary is not a daemon. Your MCP client spawns it on demand, a tool call runs, the process exits.

iCloud integration and Apple CXP (Credential Exchange Protocol) are not in this binary — a flow that names an iCloud device returns a typed "not available in this build" error.

## Build

```bash
swift build -c release --product goodboy-mcp
codesign --force --sign "Apple Development" .build/release/goodboy-mcp
```

There is no pre-built binary and no Homebrew formula. Build from source.

Keychain items are namespaced by the binary's signing identity. Ad-hoc signed binaries (the default output of `swift build`) get a new identity per build and lose their keychain grants on every rebuild. Re-signing with a stable developer identity fixes that.

## Client setup

Every client points at the same stdio binary — the envelope around the `command` entry is what changes.

### Claude Code

Claude Code writes its own config at `~/.claude.json`:

```bash
claude mcp add goodboy /absolute/path/to/.build/release/goodboy-mcp
```

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "goodboy": {
      "command": "/absolute/path/to/.build/release/goodboy-mcp"
    }
  }
}
```

### Cursor

`~/.cursor/mcp.json` — same `mcpServers` envelope as Claude Desktop.

### Windsurf

`~/.codeium/windsurf/mcp_config.json` — same `mcpServers` envelope. (Windsurf's `serverUrl` field is HTTP-only; stdio uses `command`.)

### Gemini CLI

`~/.gemini/settings.json` — same `mcpServers` envelope.

### Cline

VS Code `settings.json`, inside the `cline.mcpServers` object:

```json
{
  "cline.mcpServers": {
    "goodboy": {
      "command": "/absolute/path/to/.build/release/goodboy-mcp"
    }
  }
}
```

### VS Code

`.vscode/mcp.json` — envelope is `servers` (not `mcpServers`) and the entry declares its transport:

```json
{
  "servers": {
    "goodboy": {
      "type": "stdio",
      "command": "/absolute/path/to/.build/release/goodboy-mcp"
    }
  }
}
```

### Continue

`~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: goodboy
    command: /absolute/path/to/.build/release/goodboy-mcp
```

### Zed

`~/.config/zed/settings.json` — envelope is `context_servers`. For stdio servers, the `command` is a nested object with `path` and `args`:

```json
{
  "context_servers": {
    "goodboy": {
      "command": {
        "path": "/absolute/path/to/.build/release/goodboy-mcp",
        "args": []
      }
    }
  }
}
```

### Warp

Settings → AI → MCP Servers → Add. Paste:

```json
{
  "goodboy": {
    "command": "/absolute/path/to/.build/release/goodboy-mcp"
  }
}
```

## Tools

Twelve tools in the release build, grouped by what they touch. (Three additional tools — `goodboy_securedbox_dump`, `goodboy_securedbox_delete`, `goodboy_securedbox_clear` — are gated behind `#if DEBUG` and do not ship in release builds. Exposing them at runtime would let a prompt-injection attack hide its tracks inside `SecuredBox`.)

### Devices

- **`goodboy_tools`** — list the tool catalog (id, name, supported types, parameter schema).
- **`goodboy_devices`** — list configured devices. Reconciles via `discover()` + per-device `deviceStatus()`, and includes `lastVerifiedAt` (ISO-8601 of the most recent successful pull) and `lastAuthError` (humanized string from the most recent failed pull) when present. These are the only honest "does the stored cred still work?" signal — `check()` only probes preconditions. Idempotent, cheap enough for every page load.
- **`goodboy_device_create`** — create a device from a tool id and a config object. Used for tools that need user-supplied configuration (JSON export paths, for example) — Chrome and KeePassXC devices come from discovery.
- **`goodboy_device_edit`** — update an existing device's editable configuration. Structural parameters (Chrome profile, `chromeDir`) are immutable; recreate instead. For keychain params, use `goodboy_keychain_set`.
- **`goodboy_device_delete`** — delete one device by id. `"all"` is explicitly rejected; enumerate first so each deletion is legible in the transcript.

### Flows

- **`goodboy_run`** — execute a flow. `source` alone pulls into `SecuredBox`; `source + dest` runs a full source → destination flow; `dest` alone pushes whatever is already in `SecuredBox`. Returns the full `FlowEvent` stream and a `PreflightReport`. Concurrent flows are blocked.
- **`goodboy_flows`** — enumerate valid source → destination pairs based on type compatibility.

### SecuredBox

- **`goodboy_securedbox`** — read-only snapshot. Totals, type breakdown (passwords, with-OTP, passkeys, username-only), duplicate count. Never returns the underlying items.

### Keychain

- **`goodboy_keychain_set`** — store a keychain parameter (master passwords, Chrome Safe Storage keys, service account tokens). Per-parameter validation: `serverUrl` must be an absolute `https://` URL, `safeStorageKey` must base64-decode to exactly 16 bytes, `clientId` must be an RFC 4122 UUID, `serviceAccountToken` must start with `ops_` and be 32–256 characters. Null bytes and values over 4 KB are rejected for any key.
- **`goodboy_keychain_dev`** — dev helper. Three actions: `status` (list entries), `seed` (auto-seed Chrome/Chromium Safe Storage keys, then scan every device for missing keychain params and return an `autoSeeded` + `needsInput` manifest), and `wipe` (release builds accept `status` and `seed`; `wipe` is gated behind `#if DEBUG`).

### Chrome

- **`goodboy_chrome_profiles`** — enumerate Chrome profiles across every installed Chromium browser. Reports sync mode (`accountStorage`, `chromeSync`, `both`, `empty`), recommended profiles for writing (LDFA), and row counts for both tables (`loginData.logins`, `loginData.metadata`, `ldfa.logins`, `ldfa.metadata`). Metadata counts reveal which table is actively syncing; `empty` means no Google account is signed in.
- **`goodboy_chrome_status`** — whether Chrome is installed and whether it is currently running.

## Flow visibility

Every `goodboy_run` response carries two things:

- A **`PreflightReport`** — per-source schema mapping against the destination, listing what will transfer and which fields are lost. The report runs before execution as an honest preview; items are never removed from `SecuredBox`. Destinations receive every item and decide how to serialize partial records (a password-only record, a username-only record, a note-only record are all legitimate credentials).
- A **`FlowEvent`** stream — `started`, `reading`, `writing`, `complete`, `failed`. This is the Glass Box principle surfaced through the tool result: every subprocess spawn, database read, and external call is legible in the stream.

## Trust model

`goodboy-mcp` has no per-tool approval gate. Stdio inherently trusts its parent process, so trust is established at configuration time — pointing your MCP client at the binary authorises the client to run any tool in this document. Users are trusting their MCP client to call tools responsibly.

See [SECURITY.md](SECURITY.md) for the full trust-boundary discussion.

## What's missing

- **iCloud** — unregistered here. A `goodboy_device_create` or `goodboy_run` naming an iCloud device returns a typed "not available in this build" error.
- **Chrome Headless Write, Chrome Delete** — not in `goodboy-mcp`. This binary performs direct (Chrome-closed) reads and writes only.
