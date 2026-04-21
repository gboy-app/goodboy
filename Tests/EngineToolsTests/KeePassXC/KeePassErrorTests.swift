// Tests that all KeePassError cases have non-empty errorDescription.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("KeePassError")
struct KeePassErrorTests {

    // MARK: - All Error Cases Have Descriptions

    @Test("All error cases have non-empty errorDescription")
    func testAllCasesHaveDescription() {
        let allCases: [KeePassError] = [
            // CLI
            .cliNotFound,
            .cliExecFailed("test exec"),
            .cliInvalidOutput("test output"),
            .dbPathRequired,
            // XML / JSON
            .xmlParseFailed("test xml"),
            .jsonParseFailed("test json"),
            // General
            .notRunning,
            .databaseLocked,
            .databaseClosed,
        ]

        for error in allCases {
            let desc = error.errorDescription
            #expect(desc != nil, "Error \(error) must have errorDescription")
            #expect(!desc!.isEmpty, "Error \(error) errorDescription must be non-empty")
        }
    }

    @Test("Error count is 9 (exhaustive check)")
    func testErrorCaseCount() {
        // This serves as a sentinel — if a new case is added without tests, this fails
        let allCases: [KeePassError] = [
            .cliNotFound,
            .cliExecFailed(""),
            .cliInvalidOutput(""),
            .dbPathRequired,
            .xmlParseFailed(""),
            .jsonParseFailed(""),
            .notRunning,
            .databaseLocked,
            .databaseClosed,
        ]
        #expect(allCases.count == 9)
    }

    // MARK: - Specific Error Descriptions

    @Test("CLI errors include relevant context")
    func testCLIErrorDescriptions() {
        #expect(KeePassError.cliNotFound.errorDescription?.contains("not found") == true)
        #expect(KeePassError.cliExecFailed("timeout").errorDescription?.contains("timeout") == true)
        #expect(KeePassError.cliInvalidOutput("bad").errorDescription?.contains("bad") == true)
        #expect(KeePassError.dbPathRequired.errorDescription?.contains("path") == true)
    }

    @Test("General errors include relevant context")
    func testGeneralErrorDescriptions() {
        #expect(KeePassError.notRunning.errorDescription?.contains("not running") == true)
        #expect(KeePassError.databaseLocked.errorDescription?.contains("locked") == true)
        #expect(KeePassError.databaseClosed.errorDescription?.contains("Open a database") == true)
    }

    @Test("Error messages are actionable — tell user what to DO")
    func testErrorMessagesAreActionable() {
        // General errors → tell user to Open, Unlock
        #expect(KeePassError.notRunning.errorDescription?.contains("Open KeePassXC") == true)
        #expect(KeePassError.databaseLocked.errorDescription?.contains("Unlock") == true)
        #expect(KeePassError.databaseClosed.errorDescription?.contains("Open a database") == true)

        // CLI errors → tell user how to install
        #expect(KeePassError.cliNotFound.errorDescription?.contains("Install") == true)
        #expect(KeePassError.dbPathRequired.errorDescription?.contains("Provide") == true)
    }

    // MARK: - Error Conforms to LocalizedError

    @Test("KeePassError conforms to Error and LocalizedError")
    func testErrorConformance() {
        let error: Error = KeePassError.cliNotFound
        #expect(error.localizedDescription.contains("not found"))

        let localizedError: any LocalizedError = KeePassError.cliNotFound
        #expect(localizedError.errorDescription?.contains("not found") == true)
    }
}
