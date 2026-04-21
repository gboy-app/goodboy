// MCP handlers for the catalog + inventory tools: `goodboy_tools`,
// `goodboy_devices`, and the device-config lifecycle commands.

import Foundation
import MCP
import FlowEngine

// MARK: - Tools

func handleTools() async -> CallTool.Result {
    let hidden = mcpEffectiveHiddenTools()
    let (manifests, schemasByDriver) = await MainActor.run {
        let registry = ToolRegistry.shared
        let visible = registry.manifests.filter { !hidden.contains($0.id) }
        let schemas: [String: [DataSchemaField]] = Dictionary(uniqueKeysWithValues:
            visible.compactMap { m in
                guard let instance = registry.getTool(id: m.id) else { return nil }
                let fields = instance.dataSchema(params: [:])
                guard !fields.isEmpty else { return nil }
                return (m.id, fields)
            }
        )
        return (visible, schemas)
    }
    let items: [[String: Any]] = manifests.map { m in
        var entry: [String: Any] = [
            "id": m.id,
            "name": m.name,
            "canBeSource": m.canBeSource,
            "canBeDestination": m.canBeDestination,
            "supportedTypes": m.supportedTypes.map(\.rawValue),
            "paramSchema": m.paramSchema.map { p in
                var spec: [String: Any] = ["key": p.key, "label": p.label, "type": p.type.rawValue, "required": p.required]
                if !p.editable { spec["editable"] = false }
                return spec
            },
        ]
        if let fields = schemasByDriver[m.id] {
            entry["dataSchema"] = fields.map { f in
                ["key": f.key, "type": f.type, "required": f.required] as [String: Any]
            }
        }
        return entry
    }
    return CallTool.Result(content: [mcpText(jsonString(["count": items.count, "tools": items]))])
}

// MARK: - Devices

func handleDevices() async -> CallTool.Result {
    let startTime = ContinuousClock().now

    let hidden = mcpEffectiveHiddenTools()
    let (discoveryResult, deviceInfos, deviceSchemas) = await MainActor.run {
        let dr = DiscoveryService.discover()
        DeviceService.shared.reload()
        let registry = ToolRegistry.shared

        let infos: [DeviceInfo] = DeviceService.shared.devices
            .filter { !hidden.contains($0.tool) }
            .compactMap { device in
            guard var status = DiscoveryService.deviceStatus(for: device) else { return nil }
            if dr.changed.contains(device.id) {
                status = DeviceRuntimeStatus(
                    ready: status.ready, changed: true,
                    missing: status.missing, errors: status.errors,
                    resolvedKeychain: status.resolvedKeychain
                )
            }
            return DeviceInfo(device: device, status: status)
        }

        let schemas: [String: [DataSchemaField]] = Dictionary(uniqueKeysWithValues: infos.compactMap { info in
            guard let instance = registry.getTool(id: info.device.tool) else { return nil }
            let fields = instance.dataSchema(params: info.device.config)
            guard !fields.isEmpty else { return nil }
            return (info.device.id, fields)
        })
        return (dr, infos, schemas)
    }

    let elapsed = ContinuousClock().now - startTime
    let ms = Int(elapsed.components.seconds) * 1000
        + Int(elapsed.components.attoseconds / 1_000_000_000_000_000)

    let devices: [[String: Any]] = deviceInfos.map { info in
        let d = info.device
        let s = info.status
        var entry: [String: Any] = [
            "id": d.id,
            "tool": d.tool,
            "name": d.name,
            "canRead": d.canRead,
            "canWrite": d.canWrite,
            "config": d.config,
            "ready": s.ready,
            "changed": s.changed,
        ]
        if let sub = d.subtitle { entry["subtitle"] = sub }
        if let pn = d.profileName { entry["profileName"] = pn }
        if !s.missing.isEmpty { entry["missing"] = s.missing }
        if !s.errors.isEmpty { entry["errors"] = s.errors.map { errorDict($0) } }
        if !s.resolvedKeychain.isEmpty { entry["resolvedKeychain"] = s.resolvedKeychain }
        if let count = d.credentialCount { entry["credentialCount"] = count }
        if let verified = d.lastVerifiedAt { entry["lastVerifiedAt"] = iso8601(verified) }
        if let authError = d.lastAuthError { entry["lastAuthError"] = authError }
        if let fields = deviceSchemas[d.id] {
            entry["dataSchema"] = fields.map { f in
                ["key": f.key, "type": f.type, "required": f.required] as [String: Any]
            }
        }
        let terms = deviceSearchTerms(tool: d.tool, slug: d.slug)
        if !terms.isEmpty { entry["searchTerms"] = terms }
        return entry
    }
    var json: [String: Any] = ["count": devices.count, "devices": devices, "durationMs": ms]
    if !discoveryResult.removed.isEmpty { json["removed"] = discoveryResult.removed }
    if !discoveryResult.created.isEmpty { json["created"] = discoveryResult.created }
    return CallTool.Result(content: [mcpText(jsonString(json))])
}

/// Search aliases for device matching. Keyed by tool or "tool:slug" for slug-specific terms.
private func deviceSearchTerms(tool: String, slug: String) -> [String] {
    let toolTerms: [String: [String]] = [
        "chrome": ["chrome"],
        "keepasscli": ["keepass", "kdbx", "keepassxc"],
        "onepassword": ["1password", "onepassword"],
        "bitwarden": ["bitwarden"],
        "protonpass": ["protonpass", "proton"],
        "icloud": ["icloud", "apple passwords"],
        "json": ["json"],
    ]
    if let terms = toolTerms[tool] { return terms }

    // Chromium browser slugs (brave, edge, arc, vivaldi, opera) — slug IS the term
    if tool == "chrome",
       slug != "default" && slug != "secondary" && slug != "tertiary" && slug != "quaternary" {
        return [slug]
    }

    return []
}

// MARK: - Device Delete

func handleDeviceDelete(_ arguments: [String: Value]?) throws -> CallTool.Result {
    guard let deviceId = arguments?["deviceId"]?.stringValue else {
        throw MCPError.invalidParams("Missing required parameter 'deviceId'")
    }

    if deviceId == "all" {
        return CallTool.Result(
            content: [mcpText(jsonString([
                "error": "The 'all' sentinel is not supported. Enumerate devices via goodboy_devices and call goodboy_device_delete once per device so each deletion is legible in the transcript.",
            ]))],
            isError: true
        )
    }

    DeviceService.shared.reload()
    guard DeviceService.shared.get(id: deviceId) != nil else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Device '\(deviceId)' not found."]))],
            isError: true
        )
    }
    try DeviceService.shared.delete(id: deviceId)
    return CallTool.Result(content: [mcpText(jsonString([
        "deleted": [deviceId],
        "count": 1,
    ] as [String: Any]))])
}

// MARK: - Device Create

/// Allowed tool IDs for manual device creation.
/// Discovery handles Chrome, KeePass, and iCloud automatically.
private let creatableToolIds: Set<String> = [
    "json",
]

func handleDeviceCreate(_ arguments: [String: Value]?) async throws -> CallTool.Result {
    guard let toolId = arguments?["tool"]?.stringValue else {
        throw MCPError.invalidParams("Missing required parameter 'tool'")
    }

    guard creatableToolIds.contains(toolId) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Tool '\(toolId)' does not support manual creation. "
                + "Chrome, KeePass, and iCloud devices are auto-discovered — run goodboy_devices to see them."]))],
            isError: true
        )
    }

    let manifests = await MainActor.run { ToolRegistry.shared.manifests }
    guard let manifest = manifests.first(where: { $0.id == toolId }) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Tool '\(toolId)' not registered."]))],
            isError: true
        )
    }

    // Extract config from arguments
    var config: [String: String] = [:]
    if let configValue = arguments?["config"]?.objectValue {
        for (key, value) in configValue {
            if let s = value.stringValue { config[key] = s }
        }
    }

    // Reject keychain params in config
    for spec in manifest.paramSchema where spec.type == .keychain {
        if config[spec.key] != nil {
            return CallTool.Result(
                content: [mcpText(jsonString(["error": "Param '\(spec.key)' is a keychain param. "
                    + "Use goodboy_keychain_set after creating the device."]))],
                isError: true
            )
        }
    }

    // Reject unknown config keys
    let validKeys = Set(manifest.paramSchema.map(\.key))
    let unknownKeys = config.keys.filter { !validKeys.contains($0) }
    if !unknownKeys.isEmpty {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Unknown config keys: \(unknownKeys.sorted().joined(separator: ", ")). "
                + "Valid keys: \(validKeys.sorted().joined(separator: ", "))"]))],
            isError: true
        )
    }

    // Check required non-keychain params
    for spec in manifest.paramSchema where spec.required && spec.type != .keychain {
        if config[spec.key] == nil, spec.defaultValue == nil {
            return CallTool.Result(
                content: [mcpText(jsonString(["error": "Missing required param '\(spec.key)'. \(spec.description)"]))],
                isError: true
            )
        }
    }

    // Allocate slug
    DeviceService.shared.reload()
    let existingDevices = DeviceService.shared.devices(forTool: toolId)
    let existingIds = Set(existingDevices.map(\.id))

    let slug: String
    if let providedSlug = arguments?["slug"]?.stringValue, !providedSlug.isEmpty {
        if providedSlug.range(of: #"^[a-z0-9][a-z0-9-]{0,30}$"#, options: .regularExpression) == nil {
            return CallTool.Result(
                content: [mcpText(jsonString(["error": "Invalid slug. Slugs must match ^[a-z0-9][a-z0-9-]{0,30}$ — lowercase alphanumerics and hyphens, starting with alphanumeric, max 31 chars."]))],
                isError: true
            )
        }
        slug = providedSlug
    } else if let slugEntry = manifest.slugPool.first(where: { !existingIds.contains("\(toolId)-\($0.slug)") }) {
        slug = slugEntry.slug
    } else {
        let existingSlugs = Set(existingDevices.map(\.slug))
        if !existingSlugs.contains("default") {
            slug = "default"
        } else {
            var n = 2
            while existingSlugs.contains("default-\(n)") { n += 1 }
            slug = "default-\(n)"
        }
    }

    let deviceId = "\(toolId)-\(slug)"
    guard !existingIds.contains(deviceId) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Device '\(deviceId)' already exists."]))],
            isError: true
        )
    }

    let slugEntry = manifest.slugPool.first(where: { $0.slug == slug })
    let deviceName = slugEntry?.name ?? manifest.name

    // Merge slug preset config with user-provided config (user wins)
    var mergedConfig = (slugEntry?.config ?? [:]).filter { !$0.key.hasPrefix("_") }
    for (key, value) in config { mergedConfig[key] = value }

    let (title, subtitle) = DeviceDisplayName.compute(
        tool: toolId, slug: slug,
        deviceName: deviceName, config: mergedConfig
    )
    let category = DeviceDisplayName.category(tool: toolId)

    // Use slug-specific capabilities from the tool instance (not manifest-wide)
    let (canRead, canWrite) = await MainActor.run {
        if let instance = ToolRegistry.shared.instantiate(id: toolId) {
            return (instance.canRead(slug: slug), instance.canWrite(slug: slug))
        }
        return (manifest.canBeSource, manifest.canBeDestination)
    }

    let device = Device(
        id: deviceId,
        tool: toolId,
        slug: slug,
        name: title,
        canRead: canRead,
        canWrite: canWrite,
        config: mergedConfig,
        category: category,
        subtitle: subtitle,
        createdAt: Date()
    )

    do {
        try DeviceService.shared.save(device)
    } catch {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Failed to save device: \(error.localizedDescription)"]))],
            isError: true
        )
    }

    return CallTool.Result(content: [mcpText(jsonString([
        "deviceId": deviceId,
        "tool": toolId,
        "name": device.name,
        "config": mergedConfig,
    ] as [String: Any]))])
}

// MARK: - Device Edit

func handleDeviceEdit(_ arguments: [String: Value]?) async throws -> CallTool.Result {
    guard let deviceId = arguments?["deviceId"]?.stringValue else {
        throw MCPError.invalidParams("Missing required parameter 'deviceId'")
    }

    DeviceService.shared.reload()
    guard var device = DeviceService.shared.get(id: deviceId) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Device '\(deviceId)' not found."]))],
            isError: true
        )
    }

    let manifests = await MainActor.run { ToolRegistry.shared.manifests }
    guard let manifest = manifests.first(where: { $0.id == device.tool }) else {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Tool '\(device.tool)' not registered."]))],
            isError: true
        )
    }

    var changes: [String] = []

    // Handle config edits
    if let configValue = arguments?["config"]?.objectValue {
        var newConfig: [String: String] = [:]
        for (key, value) in configValue {
            if let s = value.stringValue { newConfig[key] = s }
        }

        if !newConfig.isEmpty {
            let schemaByKey = Dictionary(manifest.paramSchema.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })

            // Reject unknown keys
            let unknownKeys = newConfig.keys.filter { schemaByKey[$0] == nil }
            if !unknownKeys.isEmpty {
                return CallTool.Result(
                    content: [mcpText(jsonString(["error": "Unknown config keys: \(unknownKeys.sorted().joined(separator: ", ")). "
                        + "Valid keys: \(schemaByKey.keys.sorted().joined(separator: ", "))"]))],
                    isError: true
                )
            }

            // Reject keychain params
            let keychainKeys = newConfig.keys.filter { schemaByKey[$0]?.type == .keychain }
            if !keychainKeys.isEmpty {
                return CallTool.Result(
                    content: [mcpText(jsonString(["error": "Param(s) \(keychainKeys.sorted().joined(separator: ", ")) are keychain params. "
                        + "Use goodboy_keychain_set instead."]))],
                    isError: true
                )
            }

            // Reject non-editable (structural) params
            let structuralKeys = newConfig.keys.filter { schemaByKey[$0]?.editable == false }
            if !structuralKeys.isEmpty {
                return CallTool.Result(
                    content: [mcpText(jsonString(["error": "Param(s) \(structuralKeys.sorted().joined(separator: ", ")) are structural and cannot be edited. "
                        + "Create a new device instead."]))],
                    isError: true
                )
            }

            // Merge config
            for (key, value) in newConfig {
                device.config[key] = value
                changes.append("config.\(key) set to '\(value)'")
            }

            // Clear fingerprint to force re-check on next page load
            device.fingerprint = nil
        }
    }

    if changes.isEmpty {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "No changes provided. Pass config to edit."]))],
            isError: true
        )
    }

    do {
        try DeviceService.shared.save(device)
    } catch {
        return CallTool.Result(
            content: [mcpText(jsonString(["error": "Failed to save device: \(error.localizedDescription)"]))],
            isError: true
        )
    }

    return CallTool.Result(content: [mcpText(jsonString([
        "deviceId": deviceId,
        "name": device.name,
        "config": device.config,
        "changes": changes,
    ] as [String: Any]))])
}
