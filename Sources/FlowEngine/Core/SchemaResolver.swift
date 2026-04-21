// Resolves sourceDeviceId → dataSchema keys. Cached per device ID.
// This is the implementation behind BoxItem's self-awareness API.

import Foundation

/// Resolves device IDs to their data schema field keys.
/// Caches results — schema resolution is per-source, not per-record.
@MainActor
public final class SchemaResolver {

    public static let shared = SchemaResolver()

    /// Cache: deviceId → set of field keys this device produces/accepts.
    private var cache: [String: Set<String>] = [:]

    private init() {}

    /// Resolve a device ID to the set of field keys its tool declares.
    public func schemaKeys(for deviceId: String) -> Set<String>? {
        if let cached = cache[deviceId] {
            return cached
        }

        guard let device = DeviceService.shared.get(id: deviceId),
              let manifest = ToolRegistry.shared.manifests.first(where: { $0.id == device.tool }),
              let instance = ToolRegistry.shared.instantiate(id: manifest.id) else {
            return nil
        }

        let resolved = DeviceService.shared.resolveParamsForStatus(device: device, schema: manifest.paramSchema)
        let keys = Set(instance.dataSchema(params: resolved).map(\.key))
        cache[deviceId] = keys
        return keys
    }

    /// Resolve a device ID to the full DataSchemaField array.
    public func schemaFields(for deviceId: String) -> [DataSchemaField]? {
        guard let device = DeviceService.shared.get(id: deviceId),
              let manifest = ToolRegistry.shared.manifests.first(where: { $0.id == device.tool }),
              let instance = ToolRegistry.shared.instantiate(id: manifest.id) else {
            return nil
        }

        let resolved = DeviceService.shared.resolveParamsForStatus(device: device, schema: manifest.paramSchema)
        return instance.dataSchema(params: resolved)
    }

    /// Clear cache.
    public func clearCache() {
        cache.removeAll()
    }
}
