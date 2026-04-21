import Testing
import Foundation
import FlowEngine
@testable import EngineTools

@Suite("ChromeHelper — Profile Discovery")
struct ChromeHelperTests {

    /// Synthetic Chrome directory with known profiles — no real Chrome needed.
    private static func makeFakeChromeDir() throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("goodboy-test-chrome-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        let localState: [String: Any] = [
            "profile": [
                "info_cache": [
                    "Default": [
                        "name": "Alice",
                        "user_name": "alice@example.com",
                        "gaia_id": "111"
                    ],
                    "Profile 2": [
                        "name": "Bob",
                        "user_name": "bob@example.com",
                        "gaia_id": "222"
                    ],
                    "Profile 10": [
                        "name": "Charlie",
                        // no email, no gaia — unsigned profile
                    ]
                ] as [String: [String: Any]]
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: localState)
        try data.write(to: URL(fileURLWithPath: "\(dir)/Local State"))
        return dir
    }

    @Test("listProfiles parses all profiles from Local State")
    func listProfiles() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let profiles = try ChromeHelper.listProfiles(chromeDir: dir)
        #expect(profiles.count == 3)
        #expect(profiles.map(\.folder) == ["Default", "Profile 10", "Profile 2"],
                "Should be sorted by folder")
    }

    @Test("listProfiles returns deterministic order across calls")
    func listProfilesOrder() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let a = try ChromeHelper.listProfiles(chromeDir: dir)
        let b = try ChromeHelper.listProfiles(chromeDir: dir)
        #expect(a.map(\.folder) == b.map(\.folder))
    }

    @Test("resolveProfile finds profile by exact email")
    func resolveByEmail() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try ChromeHelper.resolveProfile(query: "bob@example.com", chromeDir: dir)
        let r = try #require(result)
        #expect(r.folder == "Profile 2")
        #expect(r.name == "Bob")
    }

    @Test("resolveProfile finds profile by name substring")
    func resolveByName() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try ChromeHelper.resolveProfile(query: "alice", chromeDir: dir)
        let r = try #require(result)
        #expect(r.folder == "Default")
    }

    @Test("resolveProfile finds profile by folder name")
    func resolveByFolder() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try ChromeHelper.resolveProfile(query: "Profile 10", chromeDir: dir)
        let r = try #require(result)
        #expect(r.folder == "Profile 10")
        #expect(r.name == "Charlie")
    }

    @Test("resolveProfile returns nil for unknown query")
    func resolveUnknown() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try ChromeHelper.resolveProfile(query: "nobody@nowhere.com", chromeDir: dir)
        #expect(result == nil)
    }

    @Test("detectSyncMode returns .empty for non-existent folder")
    func syncModeNonExistent() throws {
        let dir = try Self.makeFakeChromeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let mode = ChromeHelper.detectSyncMode(folder: "NoSuchProfile", chromeDir: dir)
        #expect(mode == .empty)
    }
}
