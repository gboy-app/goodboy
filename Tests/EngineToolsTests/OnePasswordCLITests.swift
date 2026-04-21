// Unit tests for 1Password CLI JSON parsing and BoxItem mapping.
// Uses mock JSON fixtures — no real `op` CLI calls.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("OnePasswordCLI")
struct OnePasswordCLITests {

    // MARK: - JSON Parsing

    @Test("OPAccount decodes from op whoami output")
    func testAccountDecode() throws {
        let json = """
        {
            "url": "https://my.1password.com",
            "email": "user@example.com",
            "user_uuid": "uuid-123",
            "account_uuid": "acc-456"
        }
        """
        let account = try JSONDecoder().decode(OPAccount.self, from: Data(json.utf8))
        #expect(account.email == "user@example.com")
        #expect(account.url == "https://my.1password.com")
    }

    @Test("OPItemSummary decodes from op item list output")
    func testItemSummaryDecode() throws {
        let json = """
        [{
            "id": "abc123",
            "title": "GitHub",
            "vault": {"id": "vault-1", "name": "Personal"},
            "category": "LOGIN",
            "favorite": true,
            "tags": ["dev", "work"],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z",
            "urls": [{"href": "https://github.com", "primary": true}]
        }]
        """
        let items = try JSONDecoder().decode([OPItemSummary].self, from: Data(json.utf8))
        #expect(items.count == 1)
        #expect(items[0].id == "abc123")
        #expect(items[0].title == "GitHub")
        #expect(items[0].category == "LOGIN")
        #expect(items[0].vault.name == "Personal")
        #expect(items[0].tags?.count == 2)
        #expect(items[0].urls?.first?.href == "https://github.com")
    }

    @Test("OPItem decodes full item with secrets")
    func testItemDecode() throws {
        let json = """
        {
            "id": "abc123",
            "title": "GitHub",
            "vault": {"id": "vault-1", "name": "Personal"},
            "category": "LOGIN",
            "favorite": false,
            "tags": null,
            "fields": [
                {"id": "username", "type": "STRING", "label": "username", "value": "user@github.com", "section": null},
                {"id": "password", "type": "CONCEALED", "label": "password", "value": "secret123", "section": null},
                {"id": "notesPlain", "type": "STRING", "label": "notesPlain", "value": "Work account", "section": null},
                {"id": "otp", "type": "OTP", "label": "one-time password", "value": "otpauth://totp/GitHub?secret=ABC", "section": null}
            ],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z",
            "urls": [
                {"href": "https://github.com", "primary": true},
                {"href": "https://github.com/login", "primary": false}
            ]
        }
        """
        let item = try JSONDecoder().decode(OPItem.self, from: Data(json.utf8))
        #expect(item.id == "abc123")
        #expect(item.fields?.count == 4)

        let username = item.fields?.first { $0.label == "username" }?.value
        #expect(username == "user@github.com")

        let password = item.fields?.first { $0.type == "CONCEALED" }?.value
        #expect(password == "secret123")

        let otp = item.fields?.first { $0.type == "OTP" }?.value
        #expect(otp == "otpauth://totp/GitHub?secret=ABC")

        #expect(item.urls?.first?.href == "https://github.com")
        #expect(item.urls?.first?.primary == true)
    }

    @Test("OPItem handles null/missing optional fields")
    func testNullSafety() throws {
        let json = """
        {
            "id": "item-2",
            "title": "Minimal",
            "vault": {"id": "vault-1", "name": null},
            "category": "LOGIN",
            "favorite": null,
            "tags": null,
            "fields": [
                {"id": "username", "type": "STRING", "label": "username", "value": null, "section": null}
            ],
            "created_at": null,
            "updated_at": null,
            "urls": null
        }
        """
        let item = try JSONDecoder().decode(OPItem.self, from: Data(json.utf8))
        #expect(item.vault.name == nil)
        #expect(item.favorite == nil)
        #expect(item.tags == nil)
        #expect(item.urls == nil)
        #expect(item.fields?[0].value == nil)
    }

    @Test("OPField with section decodes correctly")
    func testFieldWithSection() throws {
        let json = """
        {
            "id": "item-3",
            "title": "With Sections",
            "vault": {"id": "vault-1", "name": "Personal"},
            "category": "LOGIN",
            "fields": [
                {
                    "id": "custom1",
                    "type": "STRING",
                    "label": "backup_code",
                    "value": "abc-123",
                    "section": {"id": "sec1", "label": "Recovery"}
                }
            ],
            "urls": null
        }
        """
        let item = try JSONDecoder().decode(OPItem.self, from: Data(json.utf8))
        let field = item.fields?[0]
        #expect(field?.section?.label == "Recovery")
        #expect(field?.label == "backup_code")
    }

    // MARK: - BoxItem Mapping

    @Test("LOGIN item maps to BoxItem correctly")
    func testLoginToBoxItem() throws {
        let json = """
        {
            "id": "item-1",
            "title": "Netflix",
            "vault": {"id": "vault-1", "name": "Entertainment"},
            "category": "LOGIN",
            "favorite": false,
            "tags": ["streaming"],
            "fields": [
                {"id": "username", "type": "STRING", "label": "username", "value": "user@netflix.com", "section": null},
                {"id": "password", "type": "CONCEALED", "label": "password", "value": "pass123", "section": null},
                {"id": "notesPlain", "type": "STRING", "label": "notesPlain", "value": "Family plan", "section": null},
                {"id": "otp", "type": "OTP", "label": "one-time password", "value": "otpauth://totp/Netflix?secret=XYZ", "section": null}
            ],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z",
            "urls": [{"href": "https://netflix.com", "primary": true}]
        }
        """
        let item = try JSONDecoder().decode(OPItem.self, from: Data(json.utf8))
        let boxItem = mapOPItemToBoxItem(item)

        #expect(boxItem.url == "https://netflix.com")
        #expect(boxItem.username == "user@netflix.com")
        #expect(boxItem.password == "pass123")
        #expect(boxItem.extras["title"] == "Netflix")
        #expect(boxItem.extras["vault"] == "Entertainment")
        #expect(boxItem.extras["otpAuth"] == "otpauth://totp/Netflix?secret=XYZ")
        #expect(boxItem.extras["notes"] == "Family plan")
        #expect(boxItem.extras["tags"] == "streaming")
    }

    @Test("Item with no URL gets empty string")
    func testMissingURL() throws {
        let json = """
        {
            "id": "item-2",
            "title": "No URL",
            "vault": {"id": "vault-1", "name": "Personal"},
            "category": "LOGIN",
            "fields": [
                {"id": "username", "type": "STRING", "label": "username", "value": "user", "section": null},
                {"id": "password", "type": "CONCEALED", "label": "password", "value": "pass", "section": null}
            ],
            "urls": null
        }
        """
        let item = try JSONDecoder().decode(OPItem.self, from: Data(json.utf8))
        let boxItem = mapOPItemToBoxItem(item)
        #expect(boxItem.url == "")
    }

    @Test("Custom fields are extracted into extras")
    func testCustomFields() throws {
        let json = """
        {
            "id": "item-3",
            "title": "With Custom",
            "vault": {"id": "vault-1", "name": "Personal"},
            "category": "LOGIN",
            "fields": [
                {"id": "username", "type": "STRING", "label": "username", "value": "user", "section": null},
                {"id": "password", "type": "CONCEALED", "label": "password", "value": "pass", "section": null},
                {"id": "custom1", "type": "STRING", "label": "api_key", "value": "sk-abc", "section": {"id": "s1", "label": "API"}}
            ],
            "urls": [{"href": "https://example.com", "primary": true}]
        }
        """
        let item = try JSONDecoder().decode(OPItem.self, from: Data(json.utf8))
        let boxItem = mapOPItemToBoxItem(item)
        #expect(boxItem.extras["customFields"] != nil)
        #expect(boxItem.extras["customFields"]!.contains("api_key"))
    }

    // MARK: - Tool compliance

    @Test("OnePasswordCLITool has correct identity")
    func testToolIdentity() {
        #expect(OnePasswordCLITool.id == "onepassword")
        #expect(OnePasswordCLITool().canRead(slug: "default") == true)
        #expect(OnePasswordCLITool().canWrite(slug: "default") == false)
        #expect(!OnePasswordCLITool.paramSchema.isEmpty)
    }

    @Test("dataSchema returns expected fields")
    func testDataSchema() {
        let pt = OnePasswordCLITool()
        let schema = pt.dataSchema(params: [:])
        let keys = schema.map { $0.key }
        #expect(keys.contains("url"))
        #expect(keys.contains("username"))
        #expect(keys.contains("password"))
        #expect(keys.contains("otpAuth"))
        #expect(keys.contains("vault"))
    }

    // MARK: - Helpers

    /// Replicates the mapping logic from OnePasswordCLISourcePT.execute() for testability
    private func mapOPItemToBoxItem(_ item: OPItem) -> BoxItem {
        let username = item.fields?.first { $0.label == "username" }?.value ?? ""
        let password = item.fields?.first { $0.type == "CONCEALED" && ($0.label == "password" || $0.label == nil) }?.value ?? ""

        let url: String
        if let primaryUrl = item.urls?.first(where: { $0.primary == true })?.href {
            url = primaryUrl
        } else if let firstUrl = item.urls?.first?.href {
            url = firstUrl
        } else if let fieldUrl = item.fields?.first(where: { $0.type == "URL" })?.value {
            url = fieldUrl
        } else {
            url = ""
        }

        let otp = item.fields?.first { $0.type == "OTP" }?.value

        var extras: [String: String] = [:]
        extras["title"] = item.title
        if let vaultName = item.vault.name {
            extras["vault"] = vaultName
        }
        if let otp = otp, !otp.isEmpty {
            extras["otpAuth"] = otp
        }
        if let tags = item.tags, !tags.isEmpty {
            extras["tags"] = tags.joined(separator: ",")
        }
        if let notesField = item.fields?.first(where: { $0.id == "notesPlain" || $0.label == "notes" || $0.label == "notesPlain" }),
           let notes = notesField.value, !notes.isEmpty {
            extras["notes"] = notes
        }

        let standardLabels: Set<String?> = ["username", "password", "notes", "notesPlain", nil]
        let standardTypes: Set<String> = ["OTP", "URL"]
        let customFields = item.fields?.filter { field in
            !standardLabels.contains(field.label) && !standardTypes.contains(field.type) && field.id != "notesPlain"
        } ?? []
        if !customFields.isEmpty {
            let fieldDicts = customFields.map { field -> [String: String] in
                var d: [String: String] = ["type": field.type]
                if let label = field.label { d["label"] = label }
                if let value = field.value { d["value"] = value }
                if let section = field.section?.label { d["section"] = section }
                return d
            }
            if let jsonData = try? JSONSerialization.data(withJSONObject: fieldDicts),
               let jsonStr = String(data: jsonData, encoding: .utf8) {
                extras["customFields"] = jsonStr
            }
        }

        return BoxItem(url: url, username: username, password: password, extras: extras)
    }
}
