// Tool schemas advertised to MCP clients. Production set is shipped in all
// builds; DEBUG-only tools (SecuredBox dump/delete/clear) appear only in
// debug builds and are documented as such in their `description` field.

import MCP
import FlowEngine

public var allTools: [MCP.Tool] {
    var tools = productionTools
    #if DEBUG
    tools.append(contentsOf: debugOnlyTools)
    #endif
    return tools
}

private let productionTools: [MCP.Tool] = [
    MCP.Tool(
        name: "goodboy_tools",
        description: "List all registered Goodboy tools (connectors). Returns id, name, direction, supported credential types, and parameter schema for each tool.",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_devices",
        description: "List all configured Goodboy devices with current state. Each entry: ready (passed check()), errors (from check() — preconditions only, not auth), resolvedKeychain (which keychain params are stored), plus lastVerifiedAt (ISO-8601 of most recent successful pull) and lastAuthError (humanized string from most recent failed pull) when present. "
            + "The last two fields are the only honest 'does this actually work?' signal — check() probes preconditions, not auth. A device can report ready=true with lastAuthError set from a prior failed flow; treat that as 'stored creds might be stale — try a pull and find out.' "
            + "Use this instead of a separate validate call; goodboy_run itself is the real validator.",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_run",
        description: "Execute a credential flow. Pass a source device ID and optionally a destination device ID. "
            + "Both are optional: source-only = pull, source+dest = full flow, dest-only = push whatever is in SecuredBox. "
            + "Returns all flow events and the final result.",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "source": .object([
                    "type": .string("string"),
                    "description": .string("Source device ID (e.g. 'chrome-default'). Optional — omit for dest-only push.")
                ]),
                "dest": .object([
                    "type": .string("string"),
                    "description": .string("Destination device ID (e.g. 'json-default'). Optional — omit for source-only pull.")
                ])
            ])
        ])
    ),
    MCP.Tool(
        name: "goodboy_flows",
        description: "List all valid credential flow pairs (source → destination) based on type compatibility. Use this to discover what flows are possible.",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_chrome_profiles",
        description: "List Chrome browser profiles with sync mode detection. Returns folder name, display name, email, sync mode (accountStorage, chromeSync, both, empty), recommended (true for LDFA profiles ideal for writing), and row counts for both tables (loginData.logins, loginData.metadata, ldfa.logins, ldfa.metadata). Metadata counts reveal which table is actively syncing. Use this to pick the right profile for Chrome read/write operations. All syncModes except 'empty' are writable — 'empty' means no Google account is signed in.",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_chrome_status",
        description: "Chrome status: whether Chrome is installed and running.",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_device_delete",
        description: "Delete a single device by ID. Returns the deleted device ID. "
            + "To delete multiple devices, enumerate via goodboy_devices and call this once per device — "
            + "each deletion is legible in the conversation transcript.",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "deviceId": .object([
                    "type": .string("string"),
                    "description": .string("The device ID to delete (e.g. 'chrome-default').")
                ])
            ]),
            "required": .array([.string("deviceId")])
        ])
    ),
    MCP.Tool(
        name: "goodboy_keychain_set",
        description: "Securely store a keychain parameter (e.g. master password) for a device. "
            + "Pass the value directly. Use this when goodboy_devices shows a missing keychain param.",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "deviceId": .object([
                    "type": .string("string"),
                    "description": .string("The device ID (e.g. 'keepasscli-default')")
                ]),
                "paramKey": .object([
                    "type": .string("string"),
                    "description": .string("The keychain param key (e.g. 'dbPassword')")
                ]),
                "value": .object([
                    "type": .string("string"),
                    "description": .string("The value to store (e.g. the master password)")
                ])
            ]),
            "required": .array([.string("deviceId"), .string("paramKey"), .string("value")])
        ])
    ),
    MCP.Tool(
        name: "goodboy_device_create",
        description: "Create a new device manually. "
            + "Discovery handles Chrome, KeePass, and iCloud automatically — use this only for tools that need a user-specified config (e.g. JSON export with a custom path).",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "tool": .object([
                    "type": .string("string"),
                    "description": .string("The tool ID (e.g. 'json')")
                ]),
                "config": .object([
                    "type": .string("object"),
                    "description": .string("Device config values (e.g. {\"path\": \"~/Downloads/export.json\"})")
                ])
            ]),
            "required": .array([.string("tool")])
        ])
    ),
    MCP.Tool(
        name: "goodboy_device_edit",
        description: "Edit an existing device's config params. "
            + "Structural params (Chrome profile, chromeDir) cannot be edited — create a new device instead. "
            + "For keychain params (e.g. dbPassword), use goodboy_keychain_set.",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "deviceId": .object([
                    "type": .string("string"),
                    "description": .string("The device ID to edit (e.g. 'json-default')")
                ]),
                "config": .object([
                    "type": .string("object"),
                    "description": .string("Partial config to merge (e.g. {\"path\": \"~/backup.json\"}). Only editable params accepted.")
                ])
            ]),
            "required": .array([.string("deviceId")])
        ])
    ),
    MCP.Tool(
        name: "goodboy_securedbox",
        description: "Read-only snapshot of SecuredBox — the in-memory credential staging area. "
            + "Returns total count, type breakdown (passwords, withOTP, passkeys, usernameOnly), and duplicate count. "
            + "Use after a source pull to see what landed, or anytime to check current state.",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_keychain_dev",
        description: "Dev helper for Goodboy keychain management. "
            + "Actions: 'status' (list all entries), "
            + "'seed' (auto-seed browser keys for Chrome/Chromium devices, then scan ALL devices for missing keychain params "
            + "— returns autoSeeded + needsInput manifest so you can prompt the user for everything in one shot; "
            + "may trigger one macOS password prompt per browser), "
            + "'wipe' (delete all Goodboy keychain entries). "
            + "Optional 'target' for wipe: 'devices' or 'app' to wipe only one service. "
            + "Optional 'deviceId' for seed: seed/scan a specific device only.",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "action": .object([
                    "type": .string("string"),
                    "description": .string("Action to perform: 'status', 'seed', or 'wipe'")
                ]),
                "target": .object([
                    "type": .string("string"),
                    "description": .string("For wipe only: 'devices' or 'app' to wipe a specific service. Omit to wipe all.")
                ]),
                "deviceId": .object([
                    "type": .string("string"),
                    "description": .string("For seed only: seed a specific device. Omit to seed all Chrome/Chromium devices.")
                ])
            ]),
            "required": .array([.string("action")])
        ])
    ),
]

#if DEBUG
private let debugOnlyTools: [MCP.Tool] = [
    MCP.Tool(
        name: "goodboy_securedbox_clear",
        description: "DEV ONLY — clear all credentials from SecuredBox. Returns the count that was cleared. "
            + "Release builds do not expose this tool: dump/delete/clear as MCP calls is a prompt-injection "
            + "evidence-hiding path (see security audit H1).",
        inputSchema: .object(["type": .string("object"), "properties": .object([:])])
    ),
    MCP.Tool(
        name: "goodboy_securedbox_dump",
        description: "DEV ONLY — full unrestricted dump of every BoxItem in SecuredBox. "
            + "Returns all fields: url, username, password, extras (otpAuth, passkey_rpId, notes, etc). "
            + "Use to inspect the actual schema and data during development. "
            + "Optional: pass offset and limit for pagination (default: first 50 items).",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "offset": .object([
                    "type": .string("integer"),
                    "description": .string("Start index (default 0)")
                ]),
                "limit": .object([
                    "type": .string("integer"),
                    "description": .string("Max items to return (default 50)")
                ])
            ])
        ])
    ),
    MCP.Tool(
        name: "goodboy_securedbox_delete",
        description: "Delete one or more credentials from SecuredBox by index. "
            + "Returns the count deleted and an updated snapshot. "
            + "Use after goodboy_securedbox to identify which indices to remove.",
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "indices": .object([
                    "type": .string("array"),
                    "items": .object(["type": .string("integer")]),
                    "description": .string("Zero-based indices of items to delete (from goodboy_securedbox order)")
                ])
            ]),
            "required": .array([.string("indices")])
        ])
    ),
]
#endif
