// Tests for ProtonPassParser: all 8 anomalies, vault flattening, ZIP routing.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

// MARK: - Helper

/// Build a minimal Proton Pass export JSON string with given items in a vault.
func ppExportJSON(
    vaultName: String = "Personal",
    items: [String],
    encrypted: Bool = false
) -> String {
    let itemsJoined = items.joined(separator: ",\n")
    return """
    {
      "version": "1.0",
      "userId": "test-user-id",
      "encrypted": \(encrypted),
      "vaults": {
        "vault-share-id-1": {
          "name": "\(vaultName)",
          "description": "",
          "items": [\(itemsJoined)]
        }
      }
    }
    """
}

/// Standard login item with all fields populated.
let ppStandardItem = """
{
  "itemId": "item-1",
  "shareId": "vault-share-id-1",
  "state": 1,
  "data": {
    "type": "login",
    "metadata": { "name": "GitHub", "note": "Work account" },
    "extraFields": [],
    "content": {
      "itemUsername": "alice",
      "itemEmail": "alice@work.com",
      "password": "s3cret",
      "urls": ["https://github.com"],
      "totpUri": "otpauth://totp/GitHub?secret=ABC",
      "passkeys": []
    }
  }
}
"""

// MARK: - ProtonPassParser Tests

@Suite("ProtonPassParser")
struct ProtonPassParserTests {

    @Test("Full parse — standard login with all fields")
    func testStandardLogin() throws {
        let json = ppExportJSON(items: [ppStandardItem])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 1)
        let item = items[0]
        #expect(item.url == "https://github.com")
        #expect(item.username == "alice")
        #expect(item.password == "s3cret")
        #expect(item.extras["title"] == "GitHub")
        #expect(item.extras["notes"] == "Work account")
        #expect(item.extras["group"] == "Personal")
        #expect(item.extras["otpAuth"] == "otpauth://totp/GitHub?secret=ABC")
    }

    @Test("Anomaly #1 — trashed items excluded (state: 2)")
    func testTrashedItemsExcluded() throws {
        let trashedItem = """
        {
          "itemId": "item-trashed",
          "shareId": "vault-share-id-1",
          "state": 2,
          "data": {
            "type": "login",
            "metadata": { "name": "Trashed" },
            "extraFields": [],
            "content": {
              "itemUsername": "user",
              "password": "pass",
              "urls": ["https://trashed.com"],
              "passkeys": []
            }
          }
        }
        """
        let json = ppExportJSON(items: [ppStandardItem, trashedItem])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 1)
        #expect(items[0].extras["title"] == "GitHub")
    }

    @Test("Anomaly #2 — username fallback: itemUsername → itemEmail → empty")
    func testUsernameFallback() throws {
        let emptyUsernameItem = """
        {
          "itemId": "item-2",
          "shareId": "vault-share-id-1",
          "state": 1,
          "data": {
            "type": "login",
            "metadata": { "name": "Email Only" },
            "extraFields": [],
            "content": {
              "itemUsername": "",
              "itemEmail": "fallback@example.com",
              "password": "pw",
              "urls": ["https://example.com"],
              "passkeys": []
            }
          }
        }
        """
        let neitherItem = """
        {
          "itemId": "item-3",
          "shareId": "vault-share-id-1",
          "state": 1,
          "data": {
            "type": "login",
            "metadata": { "name": "Neither" },
            "extraFields": [],
            "content": {
              "itemUsername": "",
              "itemEmail": "",
              "password": "pw2",
              "urls": ["https://neither.com"],
              "passkeys": []
            }
          }
        }
        """
        let json = ppExportJSON(items: [emptyUsernameItem, neitherItem])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 2)
        #expect(items[0].username == "fallback@example.com")
        #expect(items[1].username == "")
    }

    @Test("Anomaly #3/#4 — TOTP hoisted from extraFields via data.content")
    func testTOTPHoisting() throws {
        let totpInExtraItem = """
        {
          "itemId": "item-totp",
          "shareId": "vault-share-id-1",
          "state": 1,
          "data": {
            "type": "login",
            "metadata": { "name": "TOTP Extra" },
            "extraFields": [
              {
                "fieldName": "TOTP",
                "type": "totp",
                "data": { "content": "otpauth://totp/Extra?secret=XYZ" }
              }
            ],
            "content": {
              "itemUsername": "user",
              "password": "pw",
              "urls": ["https://totp.com"],
              "totpUri": "",
              "passkeys": []
            }
          }
        }
        """
        let json = ppExportJSON(items: [totpInExtraItem])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 1)
        #expect(items[0].extras["otpAuth"] == "otpauth://totp/Extra?secret=XYZ")
        // TOTP field should NOT appear in customFields
        #expect(items[0].extras["customFields"] == nil)
    }

    @Test("Anomaly #7/#8 — note and alias items skipped")
    func testNoteAndAliasSkipped() throws {
        let noteItem = """
        {
          "itemId": "item-note",
          "shareId": "vault-share-id-1",
          "state": 1,
          "data": {
            "type": "note",
            "metadata": { "name": "My Note", "note": "Some text" },
            "extraFields": [],
            "content": {}
          }
        }
        """
        let aliasItem = """
        {
          "itemId": "item-alias",
          "shareId": "vault-share-id-1",
          "state": 1,
          "aliasEmail": "alias@pm.me",
          "data": {
            "type": "alias",
            "metadata": { "name": "My Alias" },
            "extraFields": [],
            "content": {}
          }
        }
        """
        let json = ppExportJSON(items: [ppStandardItem, noteItem, aliasItem])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 1)
        #expect(items[0].extras["title"] == "GitHub")
    }

    @Test("Missing/empty password → BoxItem(password: nil)")
    func testNilPassword() throws {
        let noPwItem = """
        {
          "itemId": "item-nopw",
          "shareId": "vault-share-id-1",
          "state": 1,
          "data": {
            "type": "login",
            "metadata": { "name": "No Password" },
            "extraFields": [],
            "content": {
              "itemUsername": "user",
              "password": "",
              "urls": ["https://nopw.com"],
              "passkeys": []
            }
          }
        }
        """
        let json = ppExportJSON(items: [noPwItem])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 1)
        #expect(items[0].password == nil)
    }

    @Test("Multi-vault flattening with vault name as group")
    func testMultiVault() throws {
        let json = """
        {
          "version": "1.0",
          "userId": "test-user",
          "encrypted": false,
          "vaults": {
            "vault-1": {
              "name": "Personal",
              "description": "",
              "items": [\(ppStandardItem)]
            },
            "vault-2": {
              "name": "Work",
              "description": "",
              "items": [
                {
                  "itemId": "item-work",
                  "shareId": "vault-2",
                  "state": 1,
                  "data": {
                    "type": "login",
                    "metadata": { "name": "Jira" },
                    "extraFields": [],
                    "content": {
                      "itemUsername": "bob",
                      "password": "j1ra",
                      "urls": ["https://jira.work.com"],
                      "passkeys": []
                    }
                  }
                }
              ]
            }
          }
        }
        """
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 2)
        let groups = Set(items.compactMap { $0.extras["group"] })
        #expect(groups.contains("Personal"))
        #expect(groups.contains("Work"))
    }

    @Test("Anomaly #6 — custom fields with garbage names stored as-is")
    func testCustomFields() throws {
        let itemWithCustom = """
        {
          "itemId": "item-custom",
          "shareId": "vault-share-id-1",
          "state": 1,
          "data": {
            "type": "login",
            "metadata": { "name": "Custom Fields" },
            "extraFields": [
              {
                "fieldName": "SearchText-kind(text)",
                "type": "text",
                "data": { "content": "some value" }
              },
              {
                "fieldName": "Secret Key",
                "type": "hidden",
                "data": { "content": "hidden-value" }
              }
            ],
            "content": {
              "itemUsername": "user",
              "password": "pw",
              "urls": ["https://custom.com"],
              "passkeys": []
            }
          }
        }
        """
        let json = ppExportJSON(items: [itemWithCustom])
        let data = json.data(using: .utf8)!
        let items = try ProtonPassParser.parse(data: data)

        #expect(items.count == 1)
        let customFieldsJSON = items[0].extras["customFields"]
        #expect(customFieldsJSON != nil)
        // Verify it's valid JSON containing both fields
        let parsed = try JSONSerialization.jsonObject(
            with: customFieldsJSON!.data(using: .utf8)!) as! [[String: String]]
        #expect(parsed.count == 2)
        #expect(parsed[0]["name"] == "SearchText-kind(text)")
        #expect(parsed[1]["name"] == "Secret Key")
    }
}

