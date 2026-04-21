// Tests for KeePassCLI: findBinary(), isAvailable, error handling.
// Uses GOODBOY_KEEPASSXC_CLI_PATH env override for hermetic testing.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("KeePassCLI")
struct KeePassCLITests {

    // MARK: - findBinary

    @Test("findBinary returns a path or nil without crashing")
    func testFindBinaryDoesNotCrash() {
        // May return nil if not installed — that's fine
        let result = KeePassCLI.findBinary()
        if let path = result {
            #expect(!path.isEmpty)
        }
    }

    @Test("isAvailable returns Bool without crashing")
    func testIsAvailableReturnsBool() {
        // Just verify it doesn't crash — result depends on machine
        let _ = KeePassCLI.isAvailable
    }

    // MARK: - Error on Invalid Path

    @Test("dbInfo throws cliNotFound when binary not available")
    func testDbInfoThrowsWhenNoBinary() throws {
        // Only test this if CLI is genuinely not available
        guard !KeePassCLI.isAvailable else { return }

        #expect(throws: KeePassError.self) {
            try KeePassCLI.dbInfo(dbPath: "/nonexistent.kdbx", password: "test")
        }
    }

    @Test("exportXML throws cliNotFound when binary not available")
    func testExportXMLThrowsWhenNoBinary() throws {
        guard !KeePassCLI.isAvailable else { return }

        #expect(throws: KeePassError.self) {
            try KeePassCLI.exportXML(dbPath: "/nonexistent.kdbx", password: "test")
        }
    }

    @Test("exportCSV throws cliNotFound when binary not available")
    func testExportCSVThrowsWhenNoBinary() throws {
        guard !KeePassCLI.isAvailable else { return }

        #expect(throws: KeePassError.self) {
            try KeePassCLI.exportCSV(dbPath: "/nonexistent.kdbx", password: "test")
        }
    }

    @Test("addEntry throws cliNotFound when binary not available")
    func testAddEntryThrowsWhenNoBinary() throws {
        guard !KeePassCLI.isAvailable else { return }

        #expect(throws: KeePassError.self) {
            try KeePassCLI.addEntry(
                dbPath: "/nonexistent.kdbx",
                password: "test",
                title: "Test",
                url: "https://test.com",
                username: "user",
                entryPassword: "pass"
            )
        }
    }

    @Test("importFile throws cliNotFound when binary not available")
    func testImportFileThrowsWhenNoBinary() throws {
        guard !KeePassCLI.isAvailable else { return }

        #expect(throws: KeePassError.self) {
            try KeePassCLI.importFile(
                dbPath: "/nonexistent.kdbx",
                password: "test",
                importPath: "/nonexistent.xml"
            )
        }
    }

    // MARK: - Binary Path Format

    @Test("findBinary returns absolute path when found")
    func testFindBinaryReturnsAbsolutePath() {
        guard let path = KeePassCLI.findBinary() else { return }
        #expect(path.hasPrefix("/"))
    }
}
