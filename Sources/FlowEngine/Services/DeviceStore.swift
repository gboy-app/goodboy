// Storage protocol for Device persistence.
// SQLiteDeviceStore for production, InMemoryDeviceStore for tests.

import Foundation

public protocol DeviceStore: Sendable {
    func loadAll() throws -> [Device]
    func save(_ device: Device) throws
    func delete(id: String) throws
}

/// In-memory store for unit tests.
public final class InMemoryDeviceStore: DeviceStore, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Device] = [:]

    public init() {}

    public func loadAll() throws -> [Device] {
        lock.lock()
        defer { lock.unlock() }
        return Array(storage.values)
    }

    public func save(_ device: Device) throws {
        lock.lock()
        defer { lock.unlock() }
        storage[device.id] = device
    }

    public func delete(id: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: id)
    }
}
