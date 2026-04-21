// SQLite-backed device persistence via GRDB.

import Foundation
import GRDB

public final class SQLiteDeviceStore: DeviceStore, @unchecked Sendable {

    private let dbQueue: DatabaseQueue

    public init() throws {
        let dbPath = AppPaths.base.appendingPathComponent("goodboy.db").path
        dbQueue = try DatabaseQueue(path: dbPath)
        // 0600 after open. GRDB creates the file with the umask default;
        // tighten it down so an attacker-user on shared hardware can't
        // peek at device configs or keychain-account layouts. Idempotent.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: dbPath
        )
        try migrate()
    }

    /// Test-friendly initializer with in-memory DB.
    public init(inMemory: Bool) throws {
        dbQueue = try DatabaseQueue()
        try migrate()
    }

    private func migrate() throws {
        var migrator = DatabaseMigrator()

        // v4: fresh schema for the rewrite. Drops old tables and creates the new one.
        // Note: the column is named "protool" here for historical parity — v8 below
        // renames it to "tool" so both fresh installs and v0.1.0 upgrades converge.
        migrator.registerMigration("v4-devices-rewrite") { db in
            // Drop old tables if they exist
            try db.execute(sql: "DROP TABLE IF EXISTS devices")
            try db.execute(sql: "DROP TABLE IF EXISTS device_pairs")

            try db.create(table: "devices") { t in
                t.primaryKey("id", .text).notNull()
                t.column("protool", .text).notNull()
                t.column("slug", .text).notNull()
                t.column("name", .text).notNull()
                t.column("canRead", .boolean).notNull().defaults(to: false)
                t.column("canWrite", .boolean).notNull().defaults(to: false)
                t.column("config", .text).notNull().defaults(to: "{}")
                t.column("category", .text).notNull().defaults(to: "")
                t.column("subtitle", .text)
                t.column("pinned", .boolean).notNull().defaults(to: false)
                t.column("lastUsed", .text)
                t.column("createdAt", .text).notNull()
                t.column("fingerprint", .text)
                t.column("credentialCount", .integer)
            }
        }
        migrator.registerMigration("v5-profileName") { db in
            try db.alter(table: "devices") { t in
                t.add(column: "profileName", .text)
            }
        }
        migrator.registerMigration("v6-lastVerifiedAt") { db in
            try db.alter(table: "devices") { t in
                t.add(column: "lastVerifiedAt", .text)
            }
        }
        migrator.registerMigration("v7-lastAuthError") { db in
            try db.alter(table: "devices") { t in
                t.add(column: "lastAuthError", .text)
            }
        }
        migrator.registerMigration("v8-rename-protool-to-tool") { db in
            try db.execute(sql: "ALTER TABLE devices RENAME COLUMN protool TO tool")
        }

        try migrator.migrate(dbQueue)
    }

    // MARK: - DeviceStore

    public func loadAll() throws -> [Device] {
        try dbQueue.read { db in
            let rows = try Row.fetchAll(db, sql: "SELECT * FROM devices ORDER BY id")
            return rows.map { Self.deviceFromRow($0) }
        }
    }

    static func deviceFromRow(_ row: Row) -> Device {
        Device(
            id: row["id"],
            tool: row["tool"],
            slug: row["slug"],
            name: row["name"],
            canRead: row["canRead"],
            canWrite: row["canWrite"],
            config: decodeConfig(row["config"]),
            category: row["category"],
            subtitle: row["subtitle"],
            profileName: row["profileName"],
            pinned: row["pinned"],
            lastUsed: decodeDate(row["lastUsed"]),
            createdAt: decodeDate(row["createdAt"]) ?? Date(),
            fingerprint: row["fingerprint"],
            credentialCount: row["credentialCount"],
            lastVerifiedAt: decodeDate(row["lastVerifiedAt"]),
            lastAuthError: row["lastAuthError"]
        )
    }

    public func save(_ device: Device) throws {
        try dbQueue.write { db in
            try db.execute(sql: """
                INSERT INTO devices (id, tool, slug, name, canRead, canWrite, config,
                    category, subtitle, profileName, pinned, lastUsed, createdAt, fingerprint,
                    credentialCount, lastVerifiedAt, lastAuthError)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    tool = excluded.tool,
                    slug = excluded.slug,
                    name = excluded.name,
                    canRead = excluded.canRead,
                    canWrite = excluded.canWrite,
                    config = excluded.config,
                    category = excluded.category,
                    subtitle = excluded.subtitle,
                    profileName = excluded.profileName,
                    pinned = CASE WHEN devices.pinned = 1 THEN 1 ELSE excluded.pinned END,
                    lastUsed = excluded.lastUsed,
                    fingerprint = excluded.fingerprint,
                    credentialCount = excluded.credentialCount,
                    lastVerifiedAt = excluded.lastVerifiedAt,
                    lastAuthError = excluded.lastAuthError
                """, arguments: [
                    device.id,
                    device.tool,
                    device.slug,
                    device.name,
                    device.canRead,
                    device.canWrite,
                    Self.encodeConfig(device.config),
                    device.category,
                    device.subtitle,
                    device.profileName,
                    device.pinned,
                    Self.encodeDate(device.lastUsed),
                    Self.encodeDate(device.createdAt),
                    device.fingerprint,
                    device.credentialCount,
                    Self.encodeDate(device.lastVerifiedAt),
                    device.lastAuthError,
                ])
        }
    }

    public func delete(id: String) throws {
        try dbQueue.write { db in
            try db.execute(sql: "DELETE FROM devices WHERE id = ?", arguments: [id])
        }
    }

    // MARK: - Helpers

    private static func encodeConfig(_ config: [String: String]) -> String {
        guard let data = try? JSONEncoder().encode(config),
              let str = String(data: data, encoding: .utf8) else { return "{}" }
        return str
    }

    private static func decodeConfig(_ raw: String?) -> [String: String] {
        guard let raw, let data = raw.data(using: .utf8),
              let dict = try? JSONDecoder().decode([String: String].self, from: data) else { return [:] }
        return dict
    }

    private static func encodeDate(_ date: Date?) -> String? {
        guard let date else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: date)
    }

    private static func decodeDate(_ raw: String?) -> Date? {
        guard let raw else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: raw)
    }
}
