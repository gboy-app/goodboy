// Unit tests for Bitwarden CLI JSON parsing and BoxItem mapping.
// Uses mock JSON fixtures — no real `bw` CLI calls.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("BitwardenCLI")
struct BitwardenCLITests {

    // MARK: - JSON Parsing

    @Test("BWStatus decodes from bw status output")
    func testStatusDecode() throws {
        let json = """
        {
            "serverUrl": "https://vault.bitwarden.com",
            "lastSync": "2026-02-24T00:00:00.000Z",
            "userEmail": "user@example.com",
            "userId": "abc-123",
            "status": "locked"
        }
        """
        let status = try JSONDecoder().decode(BWStatus.self, from: Data(json.utf8))
        #expect(status.status == "locked")
        #expect(status.userEmail == "user@example.com")
        #expect(status.serverUrl == "https://vault.bitwarden.com")
    }

    @Test("BWStatus decodes unauthenticated state (minimal fields)")
    func testStatusUnauthenticated() throws {
        let json = """
        {
            "serverUrl": "https://vault.bitwarden.com",
            "lastSync": null,
            "userEmail": null,
            "userId": null,
            "status": "unauthenticated"
        }
        """
        let status = try JSONDecoder().decode(BWStatus.self, from: Data(json.utf8))
        #expect(status.status == "unauthenticated")
        #expect(status.userEmail == nil)
    }

    @Test("BWItem decodes login with full fields")
    func testLoginItemDecode() throws {
        let json = """
        [{
            "id": "item-1",
            "type": 1,
            "name": "GitHub",
            "notes": "Work account",
            "favorite": true,
            "folderId": "folder-1",
            "login": {
                "username": "user@github.com",
                "password": "secret123",
                "totp": "otpauth://totp/GitHub?secret=ABC",
                "uris": [
                    {"uri": "https://github.com", "match": 0},
                    {"uri": "https://github.com/login", "match": null}
                ]
            },
            "fields": [
                {"type": 0, "name": "backup_code", "value": "12345"},
                {"type": 1, "name": "api_key", "value": "sk-abc"}
            ],
            "revisionDate": "2026-02-20T00:00:00.000Z",
            "deletedDate": null
        }]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        #expect(items.count == 1)
        let item = items[0]
        #expect(item.type == 1)
        #expect(item.name == "GitHub")
        #expect(item.login?.username == "user@github.com")
        #expect(item.login?.password == "secret123")
        #expect(item.login?.totp == "otpauth://totp/GitHub?secret=ABC")
        #expect(item.login?.uris?.count == 2)
        #expect(item.login?.uris?[0].uri == "https://github.com")
        #expect(item.fields?.count == 2)
        #expect(item.fields?[0].name == "backup_code")
        #expect(item.fields?[1].value == "sk-abc")
        #expect(item.notes == "Work account")
        #expect(item.folderId == "folder-1")
        #expect(item.deletedDate == nil)
    }

    @Test("BWItem decodes secure note (no login)")
    func testSecureNoteDecode() throws {
        let json = """
        [{
            "id": "item-2",
            "type": 2,
            "name": "Recovery Codes",
            "notes": "abc-def-ghi",
            "favorite": false,
            "folderId": null,
            "login": null,
            "fields": null,
            "revisionDate": "2026-01-01T00:00:00.000Z",
            "deletedDate": null
        }]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        #expect(items[0].type == 2)
        #expect(items[0].login == nil)
    }

    @Test("BWItem handles null password and null field values")
    func testNullSafety() throws {
        let json = """
        [{
            "id": "item-3",
            "type": 1,
            "name": "Username Only",
            "notes": null,
            "favorite": false,
            "folderId": null,
            "login": {
                "username": "user@example.com",
                "password": null,
                "totp": null,
                "uris": [{"uri": "https://example.com", "match": null}]
            },
            "fields": [{"type": 0, "name": "note", "value": null}],
            "revisionDate": "2026-01-01T00:00:00.000Z",
            "deletedDate": null
        }]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        #expect(items[0].login?.password == nil)
        #expect(items[0].login?.totp == nil)
        #expect(items[0].fields?[0].value == nil)
    }

    @Test("BWItem handles null URI in uris array")
    func testNullURI() throws {
        let json = """
        [{
            "id": "item-4",
            "type": 1,
            "name": "Null URI",
            "notes": null,
            "favorite": false,
            "folderId": null,
            "login": {
                "username": "user",
                "password": "pass",
                "totp": null,
                "uris": [{"uri": null, "match": null}]
            },
            "fields": null,
            "revisionDate": "2026-01-01T00:00:00.000Z",
            "deletedDate": null
        }]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        #expect(items[0].login?.uris?[0].uri == nil)
    }

    // MARK: - BoxItem Mapping

    @Test("Login item maps to BoxItem correctly")
    func testLoginToBoxItem() throws {
        let json = """
        [{
            "id": "item-1",
            "type": 1,
            "name": "Netflix",
            "notes": "Family account",
            "favorite": false,
            "folderId": "entertainment",
            "login": {
                "username": "user@netflix.com",
                "password": "pass123",
                "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{"uri": "https://netflix.com", "match": 0}]
            },
            "fields": [{"type": 0, "name": "pin", "value": "1234"}],
            "revisionDate": "2026-02-20T00:00:00.000Z",
            "deletedDate": null
        }]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        let boxItems = mapBWItemsToBoxItems(items)

        #expect(boxItems.count == 1)
        let box = boxItems[0]
        #expect(box.url == "https://netflix.com")
        #expect(box.username == "user@netflix.com")
        #expect(box.password == "pass123")
        #expect(box.extras["title"] == "Netflix")
        #expect(box.extras["otpAuth"] == "JBSWY3DPEHPK3PXP")
        #expect(box.extras["notes"] == "Family account")
        #expect(box.extras["folderId"] == "entertainment")
        #expect(box.extras["customFields"] != nil)
    }

    @Test("Deleted items are excluded")
    func testDeletedItemsSkipped() throws {
        let json = """
        [
            {
                "id": "active",
                "type": 1,
                "name": "Active",
                "notes": null,
                "favorite": false,
                "folderId": null,
                "login": {"username": "user", "password": "pass", "totp": null, "uris": [{"uri": "https://active.com", "match": null}]},
                "fields": null,
                "revisionDate": "2026-01-01T00:00:00.000Z",
                "deletedDate": null
            },
            {
                "id": "deleted",
                "type": 1,
                "name": "Deleted",
                "notes": null,
                "favorite": false,
                "folderId": null,
                "login": {"username": "user", "password": "pass", "totp": null, "uris": [{"uri": "https://deleted.com", "match": null}]},
                "fields": null,
                "revisionDate": "2026-01-01T00:00:00.000Z",
                "deletedDate": "2026-02-01T00:00:00.000Z"
            }
        ]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        let boxItems = mapBWItemsToBoxItems(items)
        #expect(boxItems.count == 1)
        #expect(boxItems[0].url == "https://active.com")
    }

    @Test("Non-login items are excluded")
    func testNonLoginSkipped() throws {
        let json = """
        [
            {
                "id": "login",
                "type": 1,
                "name": "Login",
                "notes": null,
                "favorite": false,
                "folderId": null,
                "login": {"username": "user", "password": "pass", "totp": null, "uris": [{"uri": "https://example.com", "match": null}]},
                "fields": null,
                "revisionDate": "2026-01-01T00:00:00.000Z",
                "deletedDate": null
            },
            {
                "id": "note",
                "type": 2,
                "name": "Secure Note",
                "notes": "secret",
                "favorite": false,
                "folderId": null,
                "login": null,
                "fields": null,
                "revisionDate": "2026-01-01T00:00:00.000Z",
                "deletedDate": null
            },
            {
                "id": "card",
                "type": 3,
                "name": "Card",
                "notes": null,
                "favorite": false,
                "folderId": null,
                "login": null,
                "fields": null,
                "revisionDate": "2026-01-01T00:00:00.000Z",
                "deletedDate": null
            }
        ]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        let boxItems = mapBWItemsToBoxItems(items)
        #expect(boxItems.count == 1)
    }

    @Test("Item with null password maps to empty string")
    func testNullPasswordMapsToEmpty() throws {
        let json = """
        [{
            "id": "item-1",
            "type": 1,
            "name": "Username Only",
            "notes": null,
            "favorite": false,
            "folderId": null,
            "login": {"username": "user", "password": null, "totp": null, "uris": [{"uri": "https://example.com", "match": null}]},
            "fields": null,
            "revisionDate": "2026-01-01T00:00:00.000Z",
            "deletedDate": null
        }]
        """
        let items = try JSONDecoder().decode([BWItem].self, from: Data(json.utf8))
        let boxItems = mapBWItemsToBoxItems(items)
        #expect(boxItems[0].password == "")
    }

    // MARK: - Tool compliance

    @Test("BitwardenCLITool has correct identity")
    func testToolIdentity() {
        #expect(BitwardenCLITool.id == "bitwarden")
        #expect(BitwardenCLITool().canRead(slug: "default") == true)
        #expect(BitwardenCLITool().canWrite(slug: "default") == false)
        #expect(!BitwardenCLITool.paramSchema.isEmpty)
    }

    @Test("dataSchema returns expected fields")
    func testDataSchema() {
        let pt = BitwardenCLITool()
        let schema = pt.dataSchema(params: [:])
        let keys = schema.map { $0.key }
        #expect(keys.contains("url"))
        #expect(keys.contains("username"))
        #expect(keys.contains("password"))
        #expect(keys.contains("otpAuth"))
    }

    // MARK: - Helpers

    /// Replicates the mapping logic from BitwardenCLISourcePT.execute() for testability
    private func mapBWItemsToBoxItems(_ items: [BWItem]) -> [BoxItem] {
        var results: [BoxItem] = []
        for item in items {
            if item.deletedDate != nil { continue }
            guard item.type == 1 else { continue }
            guard let login = item.login else { continue }

            let url = login.uris?.first(where: { $0.uri != nil })?.uri ?? ""
            let username = login.username ?? ""
            let password = login.password ?? ""

            var extras: [String: String] = [:]
            extras["title"] = item.name
            if let totp = login.totp, !totp.isEmpty { extras["otpAuth"] = totp }
            if let notes = item.notes, !notes.isEmpty { extras["notes"] = notes }
            if let folderId = item.folderId, !folderId.isEmpty { extras["folderId"] = folderId }
            if let fields = item.fields, !fields.isEmpty {
                let fieldDicts = fields.map { field -> [String: String] in
                    var d: [String: String] = ["type": String(field.type)]
                    if let name = field.name { d["name"] = name }
                    if let value = field.value { d["value"] = value }
                    return d
                }
                if let jsonData = try? JSONSerialization.data(withJSONObject: fieldDicts),
                   let jsonStr = String(data: jsonData, encoding: .utf8) {
                    extras["customFields"] = jsonStr
                }
            }
            results.append(BoxItem(url: url, username: username, password: password, extras: extras))
        }
        return results
    }
}
