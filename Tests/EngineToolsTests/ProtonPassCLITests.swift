// Unit tests for ProtonPass CLI JSON parsing and BoxItem mapping.
// Uses mock JSON fixtures — no real `pass-cli` calls.
// Covers all 5 documented anomalies from real Proton Pass data.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("ProtonPassCLI")
struct ProtonPassCLITests {

    // MARK: - JSON Parsing

    @Test("PPItem decodes full login item")
    func testLoginItemDecode() throws {
        let json = """
        [{
            "itemId": "item-1",
            "shareId": "share-1",
            "data": {
                "metadata": {"name": "GitHub", "note": "Work account"},
                "type": "login",
                "content": {
                    "itemUsername": "",
                    "itemEmail": "user@github.com",
                    "password": "secret123",
                    "urls": ["https://github.com"],
                    "totpUri": "otpauth://totp/GitHub?secret=ABC",
                    "passkeys": []
                },
                "extraFields": [
                    {"fieldName": "backup", "type": "text", "data": {"content": "12345"}}
                ]
            },
            "state": 1,
            "createTime": 1708300000,
            "modifyTime": 1708400000,
            "pinned": false,
            "aliasEmail": null
        }]
        """
        let items = try JSONDecoder().decode([PPItem].self, from: Data(json.utf8))
        #expect(items.count == 1)
        let item = items[0]
        #expect(item.itemId == "item-1")
        #expect(item.shareId == "share-1")
        #expect(item.data.type == "login")
        #expect(item.data.metadata.name == "GitHub")
        #expect(item.data.content.password == "secret123")
        #expect(item.data.content.urls?.first == "https://github.com")
        #expect(item.data.content.totpUri == "otpauth://totp/GitHub?secret=ABC")
        #expect(item.data.extraFields?.count == 1)
        #expect(item.state == 1)
    }

    @Test("PPItem decodes secure note (empty content)")
    func testSecureNoteDecode() throws {
        let json = """
        [{
            "itemId": "item-2",
            "shareId": "share-1",
            "data": {
                "metadata": {"name": "Recovery Codes", "note": "abc-def-ghi"},
                "type": "note",
                "content": {},
                "extraFields": null
            },
            "state": 1,
            "createTime": 1708300000,
            "modifyTime": 1708400000,
            "pinned": false,
            "aliasEmail": null
        }]
        """
        let items = try JSONDecoder().decode([PPItem].self, from: Data(json.utf8))
        #expect(items[0].data.type == "note")
        #expect(items[0].data.content.password == nil)
    }

    @Test("PPItem handles all null optional fields")
    func testNullSafety() throws {
        let json = """
        [{
            "itemId": null,
            "shareId": null,
            "data": {
                "metadata": {"name": "Minimal", "note": null},
                "type": "login",
                "content": {
                    "itemUsername": null,
                    "itemEmail": null,
                    "password": null,
                    "urls": null,
                    "totpUri": null,
                    "passkeys": null
                },
                "extraFields": null
            },
            "state": null,
            "createTime": null,
            "modifyTime": null,
            "pinned": null,
            "aliasEmail": null
        }]
        """
        let items = try JSONDecoder().decode([PPItem].self, from: Data(json.utf8))
        #expect(items[0].data.content.itemUsername == nil)
        #expect(items[0].data.content.password == nil)
        #expect(items[0].data.content.urls == nil)
    }

    // MARK: - BoxItem Mapping (anomaly coverage)

    @Test("Anomaly: empty itemUsername falls back to itemEmail")
    func testUsernameFollowsBack() throws {
        let item = makePPItem(
            itemUsername: "",
            itemEmail: "user@example.com",
            password: "pass"
        )
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.username == "user@example.com")
    }

    @Test("Anomaly: non-empty itemUsername takes priority over itemEmail")
    func testUsernamePreferred() throws {
        let item = makePPItem(
            itemUsername: "preferred_user",
            itemEmail: "email@example.com",
            password: "pass"
        )
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.username == "preferred_user")
    }

    @Test("Anomaly: TOTP in extraFields is hoisted when totpUri is empty")
    func testTotpFromExtraFields() throws {
        let item = PPItem(
            itemId: "1", shareId: "s1",
            data: PPItemData(
                metadata: PPMetadata(name: "TOTP Test", note: nil),
                type: "login",
                content: PPContent(
                    itemUsername: "user", itemEmail: nil, password: "pass",
                    urls: ["https://example.com"], totpUri: "",
                    passkeys: nil
                ),
                extraFields: [
                    PPExtraField(fieldName: "totp", type: "totp",
                                 data: PPExtraFieldData(content: "otpauth://totp/Example?secret=XYZ"))
                ]
            ),
            state: 1, createTime: nil, modifyTime: nil, pinned: nil, aliasEmail: nil
        )
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.extras["otpAuth"] == "otpauth://totp/Example?secret=XYZ")
    }

    @Test("TOTP from totpUri takes priority over extraFields")
    func testTotpUriPriority() throws {
        let item = PPItem(
            itemId: "1", shareId: "s1",
            data: PPItemData(
                metadata: PPMetadata(name: "TOTP Priority", note: nil),
                type: "login",
                content: PPContent(
                    itemUsername: "user", itemEmail: nil, password: "pass",
                    urls: ["https://example.com"],
                    totpUri: "otpauth://totp/Primary?secret=PRI",
                    passkeys: nil
                ),
                extraFields: [
                    PPExtraField(fieldName: "totp", type: "totp",
                                 data: PPExtraFieldData(content: "otpauth://totp/Secondary?secret=SEC"))
                ]
            ),
            state: 1, createTime: nil, modifyTime: nil, pinned: nil, aliasEmail: nil
        )
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.extras["otpAuth"] == "otpauth://totp/Primary?secret=PRI")
    }

    @Test("URLs are plain strings (not objects)")
    func testPlainStringURLs() throws {
        let item = makePPItem(urls: ["https://first.com", "https://second.com"])
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.url == "https://first.com")
    }

    @Test("Null password maps to empty string")
    func testNullPasswordMapsToEmpty() throws {
        let item = makePPItem(password: nil)
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.password == "")
    }

    @Test("Notes are extracted from metadata")
    func testNotesExtracted() throws {
        let item = PPItem(
            itemId: "1", shareId: "s1",
            data: PPItemData(
                metadata: PPMetadata(name: "With Notes", note: "Important note"),
                type: "login",
                content: PPContent(
                    itemUsername: "user", itemEmail: nil, password: "pass",
                    urls: ["https://example.com"], totpUri: nil, passkeys: nil
                ),
                extraFields: nil
            ),
            state: 1, createTime: nil, modifyTime: nil, pinned: nil, aliasEmail: nil
        )
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.extras["notes"] == "Important note")
    }

    @Test("Custom fields (non-totp) are extracted into extras")
    func testCustomFieldsExtracted() throws {
        let item = PPItem(
            itemId: "1", shareId: "s1",
            data: PPItemData(
                metadata: PPMetadata(name: "Custom", note: nil),
                type: "login",
                content: PPContent(
                    itemUsername: "user", itemEmail: nil, password: "pass",
                    urls: ["https://example.com"], totpUri: nil, passkeys: nil
                ),
                extraFields: [
                    PPExtraField(fieldName: "api_key", type: "hidden",
                                 data: PPExtraFieldData(content: "sk-abc")),
                    PPExtraField(fieldName: "totp", type: "totp",
                                 data: PPExtraFieldData(content: "otpauth://secret")),
                ]
            ),
            state: 1, createTime: nil, modifyTime: nil, pinned: nil, aliasEmail: nil
        )
        let box = ProtonPassCLITool.mapPPItemToBoxItem(item)
        #expect(box.extras["customFields"] != nil)
        #expect(box.extras["customFields"]!.contains("api_key"))
        // TOTP should NOT be in customFields — it's hoisted to otpAuth
        #expect(!box.extras["customFields"]!.contains("otpauth"))
    }

    // MARK: - Tool compliance

    @Test("ProtonPassCLITool has correct identity")
    func testToolIdentity() {
        #expect(ProtonPassCLITool.id == "protonpass")
        #expect(ProtonPassCLITool().canRead(slug: "default") == true)
        #expect(ProtonPassCLITool().canWrite(slug: "default") == false)
        #expect(!ProtonPassCLITool.paramSchema.isEmpty)
    }

    @Test("dataSchema returns expected fields")
    func testDataSchema() {
        let pt = ProtonPassCLITool()
        let schema = pt.dataSchema(params: [:])
        let keys = schema.map { $0.key }
        #expect(keys.contains("url"))
        #expect(keys.contains("username"))
        #expect(keys.contains("password"))
        #expect(keys.contains("otpAuth"))
    }

    // MARK: - Helpers

    private func makePPItem(
        itemUsername: String? = "user",
        itemEmail: String? = nil,
        password: String? = "pass",
        urls: [String]? = ["https://example.com"]
    ) -> PPItem {
        PPItem(
            itemId: "1", shareId: "s1",
            data: PPItemData(
                metadata: PPMetadata(name: "Test", note: nil),
                type: "login",
                content: PPContent(
                    itemUsername: itemUsername, itemEmail: itemEmail,
                    password: password, urls: urls,
                    totpUri: nil, passkeys: nil
                ),
                extraFields: nil
            ),
            state: 1, createTime: nil, modifyTime: nil, pinned: nil, aliasEmail: nil
        )
    }
}
