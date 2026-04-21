// Tests for Device model, DeviceService CRUD, param resolution,
// validation, bootstrap, and keychain management.
//
// Run: swift test --filter DeviceServiceTests

import Foundation
import Testing
import FlowEngine
@testable import FlowEngine

// MARK: - Device Codable Tests

@Suite("Device Codable")
struct DeviceCodableTests {

    @Test("Round-trip encode/decode preserves all fields")
    func testRoundTrip() throws {
        let now = Date()
        let device = Device(
            id: "chrome-default",
            tool: "chrome",
            slug: "default",
            name: "My Chrome",
            canRead: true,
            canWrite: true,
            config: ["profile": "Default"],
            lastUsed: now,
            createdAt: now
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(device)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(Device.self, from: data)

        #expect(decoded.id == "chrome-default")
        #expect(decoded.tool == "chrome")
        #expect(decoded.slug == "default")
        #expect(decoded.name == "My Chrome")
        #expect(decoded.canRead == true)
        #expect(decoded.canWrite == true)
        #expect(decoded.config["profile"] == "Default")
        #expect(decoded.lastUsed != nil)
    }

    @Test("Empty config round-trips")
    func testEmptyConfig() throws {
        let device = Device(
            id: "json-default",
            tool: "json",
            slug: "default",
            name: "JSON Export",
            canRead: false,
            canWrite: true,
            config: [:],
            createdAt: Date()
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(device)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(Device.self, from: data)

        #expect(decoded.config.isEmpty)
        #expect(decoded.lastUsed == nil)
    }
}

// MARK: - InMemoryDeviceStore Tests

@Suite("InMemoryDeviceStore")
struct InMemoryDeviceStoreTests {

    @Test("Save and loadAll")
    func testSaveAndLoad() throws {
        let store = InMemoryDeviceStore()
        let device = Device(id: "test-1", tool: "json", slug: "default", name: "Test",
                            canRead: false, canWrite: true, createdAt: Date())
        try store.save(device)
        let all = try store.loadAll()
        #expect(all.count == 1)
        #expect(all[0].id == "test-1")
    }

    @Test("Delete removes device")
    func testDelete() throws {
        let store = InMemoryDeviceStore()
        let device = Device(id: "test-1", tool: "json", slug: "default", name: "Test",
                            canRead: false, canWrite: true, createdAt: Date())
        try store.save(device)
        try store.delete(id: "test-1")
        let all = try store.loadAll()
        #expect(all.isEmpty)
    }

    @Test("Save overwrites existing device with same id")
    func testOverwrite() throws {
        let store = InMemoryDeviceStore()
        let v1 = Device(id: "d1", tool: "json", slug: "default", name: "V1",
                         canRead: false, canWrite: true, createdAt: Date())
        try store.save(v1)
        let v2 = Device(id: "d1", tool: "json", slug: "default", name: "V2",
                         canRead: false, canWrite: true, config: ["path": "/tmp"], createdAt: Date())
        try store.save(v2)
        let all = try store.loadAll()
        #expect(all.count == 1)
        #expect(all[0].name == "V2")
    }
}

// MARK: - DeviceService CRUD Tests

@Suite("DeviceService CRUD")
struct DeviceServiceCRUDTests {

    private func makeService() -> DeviceService {
        DeviceService(store: InMemoryDeviceStore())
    }

    @Test("Save and get device")
    func testSaveGet() throws {
        let svc = makeService()
        let device = Device(id: "json-default", tool: "json", slug: "default",
                            name: "JSON Export", canRead: false, canWrite: true,
                            createdAt: Date())
        try svc.save(device)
        let got = svc.get(id: "json-default")
        #expect(got != nil)
        #expect(got?.name == "JSON Export")
    }

    @Test("devices(forTool:) filters correctly")
    func testDevicesForTool() throws {
        let svc = makeService()
        try svc.save(Device(id: "keepasscli-default", tool: "keepasscli", slug: "default", name: "A",
                            canRead: true, canWrite: true, createdAt: Date()))
        try svc.save(Device(id: "keepasscli-secondary", tool: "keepasscli", slug: "secondary", name: "B",
                            canRead: true, canWrite: true, createdAt: Date()))
        try svc.save(Device(id: "json-default", tool: "json", slug: "default", name: "JSON",
                            canRead: false, canWrite: true, createdAt: Date()))

        #expect(svc.devices(forTool: "keepasscli").count == 2)
        #expect(svc.devices(forTool: "json").count == 1)
        #expect(svc.devices(forTool: "chrome").isEmpty)
    }

    @Test("Delete removes device")
    func testDelete() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "json", slug: "default", name: "D1",
                            canRead: false, canWrite: true, createdAt: Date()))
        try svc.delete(id: "d1")
        #expect(svc.get(id: "d1") == nil)
        #expect(svc.devices.isEmpty)
    }

    @Test("Save updates existing device")
    func testUpdate() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "json", slug: "default", name: "Original",
                            canRead: false, canWrite: true, createdAt: Date()))
        try svc.save(Device(id: "d1", tool: "json", slug: "default", name: "Updated",
                            canRead: false, canWrite: true, config: ["path": "/tmp"], createdAt: Date()))

        #expect(svc.devices.count == 1)
        #expect(svc.get(id: "d1")?.name == "Updated")
        #expect(svc.get(id: "d1")?.config["path"] == "/tmp")
    }
}

// MARK: - Param Resolution Tests

@Suite("DeviceService resolveParams")
struct DeviceServiceResolveParamsTests {

    private func makeService() -> DeviceService {
        DeviceService(store: InMemoryDeviceStore())
    }

    @Test("Override wins over device config")
    func testOverrideWins() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "keepasscli", slug: "default", name: "D1",
                            canRead: true, canWrite: true, config: ["path": "/saved"],
                            createdAt: Date()))
        let device = svc.get(id: "d1")!
        let schema = [ParamSpec(key: "path", label: "File Path", type: .path,
                                required: true, description: "Path to CSV")]

        let resolved = svc.resolveParams(device: device, schema: schema,
                                          overrides: ["path": "/override"])
        #expect(resolved["path"] == "/override")
    }

    @Test("Device config used when no override")
    func testDeviceConfig() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "keepasscli", slug: "default", name: "D1",
                            canRead: true, canWrite: true, config: ["path": "/saved"],
                            createdAt: Date()))
        let device = svc.get(id: "d1")!
        let schema = [ParamSpec(key: "path", label: "File Path", type: .path,
                                required: true, description: "Path to CSV")]

        let resolved = svc.resolveParams(device: device, schema: schema)
        #expect(resolved["path"] == "/saved")
    }

    @Test("Schema default used as fallback")
    func testSchemaDefault() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "json", slug: "default", name: "D1",
                            canRead: false, canWrite: true,
                            createdAt: Date()))
        let device = svc.get(id: "d1")!
        let schema = [ParamSpec(key: "format", label: "Format", type: .string,
                                required: false, description: "Output format",
                                defaultValue: "csv")]

        let resolved = svc.resolveParams(device: device, schema: schema)
        #expect(resolved["format"] == "csv")
    }

    @Test("Missing param with no default returns empty")
    func testMissingParam() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "json", slug: "default", name: "D1",
                            canRead: false, canWrite: true,
                            createdAt: Date()))
        let device = svc.get(id: "d1")!
        let schema = [ParamSpec(key: "path", label: "File Path", type: .path,
                                required: true, description: "Path")]

        let resolved = svc.resolveParams(device: device, schema: schema)
        #expect(resolved["path"] == nil)
    }

    @Test("Multiple params resolve independently")
    func testMultipleParams() throws {
        let svc = makeService()
        try svc.save(Device(id: "d1", tool: "keepasscli", slug: "default", name: "D1",
                            canRead: true, canWrite: true, config: ["path": "/config-path"],
                            createdAt: Date()))
        let device = svc.get(id: "d1")!
        let schema = [
            ParamSpec(key: "path", label: "Path", type: .path, required: true, description: "File"),
            ParamSpec(key: "format", label: "Format", type: .string, required: false,
                      description: "Output format", defaultValue: "json"),
        ]

        let resolved = svc.resolveParams(device: device, schema: schema,
                                          overrides: ["format": "csv"])
        #expect(resolved["path"] == "/config-path")
        #expect(resolved["format"] == "csv")
    }
}

// MARK: - Validation Tests

@Suite("DeviceService resolveDevice")
struct DeviceServiceValidationTests {

    private func makeService() -> DeviceService {
        DeviceService(store: InMemoryDeviceStore())
    }

    @Test("Unknown device returns actionable error")
    @MainActor
    func testUnknownDevice() {
        let svc = makeService()
        let result = svc.resolveDevice(id: "nonexistent")
        guard case .failure(let errors) = result else {
            Issue.record("Expected failure for unknown device")
            return
        }
        #expect(errors.messages.count == 1)
        #expect(errors.messages[0].message.contains("not found"))
        #expect(errors.messages[0].message.contains("goodboy devices"))
    }
}

// MARK: - Bootstrap Tests

@Suite("DeviceService bootstrapDefaults")
struct DeviceServiceBootstrapTests {

    private func makeService() -> DeviceService {
        DeviceService(store: InMemoryDeviceStore())
    }

    @Test("Bootstrap only creates pre-built devices (zero-config drivers)")
    @MainActor
    func testBootstrapCreatesOnlyPrebuilt() {
        let svc = makeService()
        svc.bootstrapDefaults()

        // icloud gets a pre-built device only on macOS 26+
        let icloudRegistered = ToolRegistry.shared.manifests.contains { $0.id == "icloud" }
        let icloudDevices = svc.devices(forTool: "icloud")
        if icloudRegistered {
            #expect(icloudDevices.count == 1)
            #expect(icloudDevices[0].id == "icloud-default")
        } else {
            #expect(icloudDevices.isEmpty)
        }

        // Other tools should never have devices
        let chromeDevices = svc.devices(forTool: "chrome")
        #expect(chromeDevices.isEmpty)
    }

    @Test("Bootstrap skips tool that already has a device")
    @MainActor
    func testBootstrapSkipsExisting() throws {
        let svc = makeService()
        try svc.save(Device(id: "json-custom", tool: "json", slug: "custom", name: "Custom",
                            canRead: false, canWrite: true, createdAt: Date()))

        svc.bootstrapDefaults()

        let jsonDevices = svc.devices(forTool: "json")
        #expect(jsonDevices.count == 1)
        #expect(jsonDevices[0].id == "json-custom")
    }

    @Test("Bootstrap is idempotent")
    @MainActor
    func testBootstrapIdempotent() {
        let svc = makeService()
        svc.bootstrapDefaults()
        let countAfterFirst = svc.devices.count
        svc.bootstrapDefaults()
        #expect(svc.devices.count == countAfterFirst)
    }
}

// MARK: - Keychain Tests

@Suite("DeviceService Keychain")
struct DeviceServiceKeychainTests {

    private static let testDeviceId = "test-keychain-device"
    private static let testParamKey = "dbPassword"

    private func makeService() -> DeviceService {
        DeviceService(store: InMemoryDeviceStore(), keychain: InMemoryKeychain())
    }

    @Test("Set and get keychain round-trip")
    func testSetGetKeychain() throws {
        let svc = makeService()

        try svc.setKeychain(deviceId: Self.testDeviceId, paramKey: Self.testParamKey, value: "s3cret")
        let loaded = svc.getKeychain(deviceId: Self.testDeviceId, paramKey: Self.testParamKey)
        #expect(loaded == "s3cret")
    }

    @Test("Getting nonexistent keychain param returns nil")
    func testLoadMissing() {
        let svc = makeService()
        let loaded = svc.getKeychain(deviceId: "no-such-device", paramKey: "nokey")
        #expect(loaded == nil)
    }

    @Test("Set overwrites existing keychain param")
    func testOverwrite() throws {
        let svc = makeService()

        try svc.setKeychain(deviceId: Self.testDeviceId, paramKey: Self.testParamKey, value: "old")
        try svc.setKeychain(deviceId: Self.testDeviceId, paramKey: Self.testParamKey, value: "new")
        let loaded = svc.getKeychain(deviceId: Self.testDeviceId, paramKey: Self.testParamKey)
        #expect(loaded == "new")
    }

    @Test("Keychain param used in resolveParams priority chain")
    func testKeychainInResolveParams() throws {
        let svc = makeService()

        try svc.save(Device(id: Self.testDeviceId, tool: "keepasscli", slug: "default", name: "Test",
                            canRead: true, canWrite: true, createdAt: Date()))
        try svc.setKeychain(deviceId: Self.testDeviceId, paramKey: Self.testParamKey, value: "secret-pw")

        let device = svc.get(id: Self.testDeviceId)!
        let schema = [ParamSpec(key: Self.testParamKey, label: "Password", type: .keychain,
                                required: true, description: "DB password")]

        let resolved = svc.resolveParams(device: device, schema: schema)
        #expect(resolved[Self.testParamKey] == "secret-pw")
    }
}

// MARK: - Keychain Status & Wipe Tests

@Suite("DeviceService keychainStatus & wipeKeychain")
struct DeviceServiceKeychainDevTests {

    private func makeService() -> DeviceService {
        DeviceService(store: InMemoryDeviceStore(), keychain: InMemoryKeychain())
    }

    @Test("keychainStatus returns both services")
    func testStatusReturnsBothServices() {
        let svc = makeService()
        let status = svc.keychainStatus()
        #expect(status.services.count == 2)
        #expect(status.services[0].service == "app.gboy.goodboy.devices")
        #expect(status.services[1].service == "app.gboy.goodboy")
    }

    @Test("keychainStatus reflects stored entries")
    func testStatusReflectsEntries() throws {
        let svc = makeService()
        try svc.setKeychain(deviceId: "d1", paramKey: "pw", value: "secret")
        let status = svc.keychainStatus()
        let deviceAccounts = status.services[0].accounts
        #expect(deviceAccounts.contains("d1.pw"))
    }

    @Test("wipeKeychain devices clears device entries")
    func testWipeDevices() throws {
        let svc = makeService()
        try svc.setKeychain(deviceId: "d1", paramKey: "pw", value: "secret")
        let result = svc.wipeKeychain(target: "devices")
        #expect(!result.wiped.isEmpty)
        #expect(svc.getKeychain(deviceId: "d1", paramKey: "pw") == nil)
    }

    @Test("wipeKeychain nil clears both services")
    func testWipeAll() throws {
        let svc = makeService()
        try svc.setKeychain(deviceId: "d1", paramKey: "pw", value: "secret")
        let result = svc.wipeKeychain()
        #expect(!result.wiped.isEmpty)
        #expect(result.message.contains("Wiped"))
    }

    @Test("wipeKeychain unknown target returns error message")
    func testWipeUnknown() {
        let svc = makeService()
        let result = svc.wipeKeychain(target: "bogus")
        #expect(result.wiped.isEmpty)
        #expect(result.message.contains("Unknown target"))
    }
}

// MARK: - Seed Keychain Tests

/// Mock tool with a .keychain param for testing seedKeychain().
final class MockKeychainSource: Tool {
    static let id = "mockkc-source"
    static let name = "Mock KC Source"
    static let description = "Source with keychain param"
    static let supportedTypes: [BoxItemType] = [.password]
    static var paramSchema: [ParamSpec] { [
        ParamSpec(key: "dbPath", label: "Database Path", type: .path, required: true, description: "Path to DB"),
        ParamSpec(key: "dbPassword", label: "Database Password", type: .keychain, required: true, description: "Master password"),
    ] }
    static var slugPool: [SlugEntry] { [SlugEntry(slug: "default", name: "Default")] }
    init() {}
    func canRead(slug: String) -> Bool { true }
    func canWrite(slug: String) -> Bool { false }
    func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        .failure("mock")
    }
}

/// Mock dest for the same tool pair.
final class MockKeychainDest: Tool {
    static let id = "mockkc-dest"
    static let name = "Mock KC Dest"
    static let description = "Dest with keychain param"
    static let supportedTypes: [BoxItemType] = [.password]
    static var paramSchema: [ParamSpec] { [
        ParamSpec(key: "dbPath", label: "Database Path", type: .path, required: true, description: "Path to DB"),
        ParamSpec(key: "dbPassword", label: "Database Password", type: .keychain, required: true, description: "Master password"),
    ] }
    static var slugPool: [SlugEntry] { [SlugEntry(slug: "default", name: "Default")] }
    init() {}
    func canRead(slug: String) -> Bool { false }
    func canWrite(slug: String) -> Bool { true }
    func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        .failure("mock")
    }
}

@Suite("DeviceService seedKeychain")
struct DeviceServiceSeedTests {

    @MainActor
    private func makeServiceWithRegistry() -> DeviceService {
        let registry = ToolRegistry()
        registry.registerBundled([MockKeychainSource.self, MockKeychainDest.self])
        return DeviceService(store: InMemoryDeviceStore(), registry: registry, keychain: InMemoryKeychain())
    }

    @Test("Seed with no devices returns empty result")
    @MainActor
    func testSeedNoDevices() {
        let svc = makeServiceWithRegistry()
        let result = svc.seedKeychain()
        #expect(result.success == true)
        #expect(result.autoSeeded.isEmpty)
        #expect(result.needsInput.isEmpty)
        #expect(result.errors.isEmpty)
    }

    @Test("Seed reports needsInput for missing keychain params")
    @MainActor
    func testSeedNeedsInput() throws {
        let svc = makeServiceWithRegistry()
        try svc.save(Device(id: "mockkc-source-default", tool: "mockkc-source", slug: "default", name: "Test",
                            canRead: true, canWrite: false, config: ["dbPath": "/tmp/test.kdbx"],
                            createdAt: Date()))
        let result = svc.seedKeychain()
        #expect(result.needsInput.count == 1)
        #expect(result.needsInput[0].paramKey == "dbPassword")
        #expect(result.needsInput[0].label == "Database Password")
        #expect(result.needsInput[0].required == true)
    }

    @Test("Seed deduplicates devices with same keychain param")
    @MainActor
    func testSeedDeduplicates() throws {
        let svc = makeServiceWithRegistry()
        try svc.save(Device(id: "mockkc-source-default", tool: "mockkc-source", slug: "default", name: "Source",
                            canRead: true, canWrite: false, config: ["dbPath": "/tmp/test.kdbx"],
                            createdAt: Date()))
        try svc.save(Device(id: "mockkc-dest-default", tool: "mockkc-dest", slug: "default", name: "Dest",
                            canRead: false, canWrite: true, config: ["dbPath": "/tmp/test.kdbx"],
                            createdAt: Date()))
        let result = svc.seedKeychain()
        // Different device IDs → separate needsInput entries (dedup is per device+param)
        #expect(result.needsInput.count == 2)
    }

    @Test("Seed skips already-cached keychain params")
    @MainActor
    func testSeedSkipsCached() throws {
        let svc = makeServiceWithRegistry()
        try svc.save(Device(id: "mockkc-source-default", tool: "mockkc-source", slug: "default", name: "Test",
                            canRead: true, canWrite: false, config: ["dbPath": "/tmp/test.kdbx"],
                            createdAt: Date()))
        try svc.setKeychain(deviceId: "mockkc-source-default", paramKey: "dbPassword", value: "alreadyset")
        let result = svc.seedKeychain()
        #expect(result.needsInput.isEmpty)
    }

    @Test("Seed with extractBrowserKey closure invokes it for Chrome devices")
    @MainActor
    func testSeedCallsExtractForChromeDevice() throws {
        let registry = ToolRegistry()
        registry.registerBundled([MockChromeSource.self])
        let svc = DeviceService(store: InMemoryDeviceStore(), registry: registry, keychain: InMemoryKeychain())

        try svc.save(Device(id: "chrome-default", tool: "chrome", slug: "default", name: "Chrome",
                            canRead: true, canWrite: true, config: ["chromeDir": "/fake/chrome"],
                            createdAt: Date()))

        var extractCalled = false
        let result = svc.seedKeychain(extractBrowserKey: { chromeDir in
            extractCalled = true
            #expect(chromeDir == "/fake/chrome")
            return "fakeKeyB64"
        })

        #expect(extractCalled)
        #expect(result.autoSeeded.count == 1)
        #expect(result.autoSeeded[0].alreadyCached == false)
        #expect(svc.getKeychain(deviceId: "chrome-default", paramKey: "safeStorageKey") == "fakeKeyB64")
    }

    @Test("Seed with unknown targetDeviceId returns error")
    @MainActor
    func testSeedUnknownDevice() {
        let svc = makeServiceWithRegistry()
        let result = svc.seedKeychain(targetDeviceId: "nonexistent")
        #expect(result.success == false)
        #expect(result.errors.count == 1)
        #expect(result.errors[0].message.contains("not found"))
    }
}

/// Mock Chrome source tool for testing auto-seed.
final class MockChromeSource: Tool {
    static let id = "chrome"
    static let name = "Chrome"
    static let description = "Mock Chrome source"
    static let supportedTypes: [BoxItemType] = [.password]
    static var paramSchema: [ParamSpec] { [
        ParamSpec(key: "chromeDir", label: "Chrome Directory", type: .path, required: false,
                  description: "Chrome data dir"),
        ParamSpec(key: "safeStorageKey", label: "Encryption Key", type: .keychain, required: true,
                  description: "Browser encryption key"),
    ] }
    static var slugPool: [SlugEntry] { [SlugEntry(slug: "default", name: "Default")] }
    init() {}
    func canRead(slug: String) -> Bool { true }
    func canWrite(slug: String) -> Bool { true }
    func execute(action: ToolAction, params: [String: String], securedBox: SecuredBox) async throws -> ToolResult {
        .failure("mock")
    }
}
