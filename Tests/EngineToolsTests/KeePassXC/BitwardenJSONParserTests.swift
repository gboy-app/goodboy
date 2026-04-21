// Tests for BitwardenJSONParser: known Bitwarden JSON structures,
// passkey mapping, field extraction, error handling.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("BitwardenJSONParser")
struct BitwardenJSONParserTests {

    // MARK: - Test Fixtures

    /// Minimal Bitwarden export with a single login item.
    static let minimalExport = """
    {
        "encrypted": false,
        "folders": [],
        "items": [
            {
                "id": "item-1",
                "folderId": null,
                "type": 1,
                "name": "Example Login",
                "notes": null,
                "favorite": false,
                "login": {
                    "username": "user@example.com",
                    "password": "hunter2",
                    "totp": null,
                    "uris": [
                        {"uri": "https://example.com/login", "match": null}
                    ],
                    "fido2Credentials": []
                }
            }
        ]
    }
    """

    /// Export with a passkey-enabled login.
    static let passkeyExport = """
    {
        "encrypted": false,
        "folders": [
            {"id": "folder-1", "name": "Work"}
        ],
        "items": [
            {
                "id": "item-pk",
                "folderId": "folder-1",
                "type": 1,
                "name": "GitHub Passkey",
                "notes": "My GitHub passkey login",
                "favorite": true,
                "login": {
                    "username": "user@github.com",
                    "password": null,
                    "totp": null,
                    "uris": [
                        {"uri": "https://github.com", "match": null}
                    ],
                    "fido2Credentials": [
                        {
                            "credentialId": "Y3JlZGVudGlhbElk",
                            "keyType": "public-key",
                            "keyAlgorithm": "ECDSA",
                            "keyCurve": "P-256",
                            "keyValue": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
                            "rpId": "github.com",
                            "rpName": "GitHub",
                            "userHandle": "dXNlcl9oYW5kbGU=",
                            "userName": "user@github.com",
                            "userDisplayName": "Test User",
                            "counter": "0",
                            "discoverable": "true",
                            "creationDate": "2025-01-01T00:00:00.000Z"
                        }
                    ]
                }
            }
        ]
    }
    """

    /// Export with mixed item types (only type 1 should be parsed).
    static let mixedTypesExport = """
    {
        "encrypted": false,
        "folders": [],
        "items": [
            {
                "id": "login-item",
                "folderId": null,
                "type": 1,
                "name": "Login Item",
                "notes": null,
                "favorite": false,
                "login": {
                    "username": "user",
                    "password": "pass",
                    "totp": null,
                    "uris": [{"uri": "https://login.com", "match": null}],
                    "fido2Credentials": []
                }
            },
            {
                "id": "note-item",
                "folderId": null,
                "type": 2,
                "name": "Secure Note",
                "notes": "Secret stuff",
                "favorite": false,
                "secureNote": {"type": 0}
            },
            {
                "id": "card-item",
                "folderId": null,
                "type": 3,
                "name": "My Card",
                "notes": null,
                "favorite": false,
                "card": {
                    "cardholderName": "John",
                    "brand": "Visa",
                    "number": "4111111111111111",
                    "expMonth": "12",
                    "expYear": "2028",
                    "code": "123"
                }
            }
        ]
    }
    """

    // MARK: - Basic Parsing

    @Test("Parses minimal login item")
    func testMinimalLogin() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.minimalExport)

        #expect(creds.count == 1)
        let cred = creds[0]
        #expect(cred.url == "https://example.com/login")
        #expect(cred.username == "user@example.com")
        #expect(cred.password == "hunter2")
        #expect(cred.extras["title"] == "Example Login")
    }

    @Test("Returns empty array for export with no items")
    func testEmptyItems() throws {
        let json = """
        {"encrypted": false, "folders": [], "items": []}
        """
        let creds = try BitwardenJSONParser.parse(json: json)
        #expect(creds.isEmpty)
    }

    @Test("Only parses login items (type 1)")
    func testOnlyLoginItems() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.mixedTypesExport)

        #expect(creds.count == 1)
        #expect(creds[0].extras["title"] == "Login Item")
    }

    // MARK: - Passkey Extraction

    @Test("Extracts fido2Credentials into passkey extras")
    func testPasskeyExtraction() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.passkeyExport)

        #expect(creds.count == 1)
        let cred = creds[0]

        #expect(cred.extras[PasskeyExtrasKey.rpId] == "github.com")
        #expect(cred.extras[PasskeyExtrasKey.credentialId] == "Y3JlZGVudGlhbElk")
        #expect(cred.extras[PasskeyExtrasKey.userHandle] == "dXNlcl9oYW5kbGU=")
        #expect(cred.extras[PasskeyExtrasKey.username] == "user@github.com")
        #expect(cred.extras[PasskeyExtrasKey.privateKeyPEM]?.hasPrefix("-----BEGIN PRIVATE KEY-----") == true)
        #expect(cred.extras[PasskeyExtrasKey.privateKeyPEM]?.contains("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg") == true)
    }

    @Test("Password is nil for passkey-only login")
    func testPasskeyOnlyNilPassword() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.passkeyExport)

        #expect(creds.count == 1)
        #expect(creds[0].password == nil)
    }

    @Test("Empty fido2Credentials array produces no passkey extras")
    func testEmptyFido2Credentials() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.minimalExport)

        #expect(creds.count == 1)
        #expect(creds[0].extras[PasskeyExtrasKey.rpId] == nil)
        #expect(creds[0].extras[PasskeyExtrasKey.credentialId] == nil)
    }

    // MARK: - Folder Mapping

    @Test("Maps folderId to folder name in extras")
    func testFolderMapping() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.passkeyExport)

        #expect(creds.count == 1)
        #expect(creds[0].extras["group"] == "Work")
    }

    @Test("No group extra when folderId is null")
    func testNullFolderId() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.minimalExport)

        #expect(creds[0].extras["group"] == nil)
    }

    // MARK: - TOTP

    @Test("Extracts TOTP as otpAuth extra")
    func testTOTP() throws {
        let json = """
        {
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "id": "totp-item",
                    "folderId": null,
                    "type": 1,
                    "name": "TOTP Site",
                    "notes": null,
                    "favorite": false,
                    "login": {
                        "username": "user",
                        "password": "pass",
                        "totp": "otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP",
                        "uris": [{"uri": "https://totp.com", "match": null}],
                        "fido2Credentials": []
                    }
                }
            ]
        }
        """

        let creds = try BitwardenJSONParser.parse(json: json)

        #expect(creds.count == 1)
        #expect(creds[0].extras["otpAuth"] == "otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP")
    }

    // MARK: - Notes

    @Test("Extracts notes into extras")
    func testNotes() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.passkeyExport)

        #expect(creds[0].extras["notes"] == "My GitHub passkey login")
    }

    @Test("No notes extra when notes is null")
    func testNullNotes() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.minimalExport)

        #expect(creds[0].extras["notes"] == nil)
    }

    // MARK: - Multiple URIs

    @Test("Uses first URI for credential URL")
    func testMultipleURIs() throws {
        let json = """
        {
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "id": "multi-uri",
                    "folderId": null,
                    "type": 1,
                    "name": "Multi URI",
                    "notes": null,
                    "favorite": false,
                    "login": {
                        "username": "user",
                        "password": "pass",
                        "totp": null,
                        "uris": [
                            {"uri": "https://primary.com", "match": null},
                            {"uri": "https://secondary.com", "match": null}
                        ],
                        "fido2Credentials": []
                    }
                }
            ]
        }
        """

        let creds = try BitwardenJSONParser.parse(json: json)
        #expect(creds[0].url == "https://primary.com")
    }

    @Test("Empty URL when no URIs present")
    func testNoURIs() throws {
        let json = """
        {
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "id": "no-uri",
                    "folderId": null,
                    "type": 1,
                    "name": "No URI Item",
                    "notes": null,
                    "favorite": false,
                    "login": {
                        "username": "user",
                        "password": "pass",
                        "totp": null,
                        "uris": [],
                        "fido2Credentials": []
                    }
                }
            ]
        }
        """

        let creds = try BitwardenJSONParser.parse(json: json)
        #expect(creds[0].url == "")
    }

    // MARK: - Error Handling

    @Test("Throws on encrypted export")
    func testEncryptedExport() throws {
        let json = """
        {"encrypted": true, "folders": [], "items": []}
        """

        #expect(throws: KeePassError.self) {
            try BitwardenJSONParser.parse(json: json)
        }
    }

    @Test("Throws on invalid JSON")
    func testInvalidJSON() throws {
        #expect(throws: KeePassError.self) {
            try BitwardenJSONParser.parse(json: "not valid json")
        }
    }

    @Test("Throws on malformed structure")
    func testMalformedStructure() throws {
        let json = """
        {"encrypted": false, "items": "not an array"}
        """

        #expect(throws: KeePassError.self) {
            try BitwardenJSONParser.parse(json: json)
        }
    }

    // MARK: - keyValue Encoding

    @Test("keyValue is converted to PEM format")
    func testKeyValueEncoding() throws {
        let creds = try BitwardenJSONParser.parse(json: Self.passkeyExport)

        let keyValue = creds[0].extras[PasskeyExtrasKey.privateKeyPEM]
        #expect(keyValue != nil)

        // Should be PEM-wrapped PKCS#8
        #expect(keyValue?.hasPrefix("-----BEGIN PRIVATE KEY-----") == true)
        #expect(keyValue?.hasSuffix("-----END PRIVATE KEY-----") == true)

        // Extract the Base64 content between PEM headers and verify it's valid
        if let pem = keyValue {
            let body = pem
                .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----\n", with: "")
                .replacingOccurrences(of: "\n-----END PRIVATE KEY-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
            #expect(Data(base64Encoded: body) != nil)
        }
    }

    // MARK: - Multiple Logins

    @Test("Parses multiple login items")
    func testMultipleLogins() throws {
        let json = """
        {
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "id": "item-1",
                    "folderId": null,
                    "type": 1,
                    "name": "Site A",
                    "notes": null,
                    "favorite": false,
                    "login": {
                        "username": "userA",
                        "password": "passA",
                        "totp": null,
                        "uris": [{"uri": "https://a.com", "match": null}],
                        "fido2Credentials": []
                    }
                },
                {
                    "id": "item-2",
                    "folderId": null,
                    "type": 1,
                    "name": "Site B",
                    "notes": null,
                    "favorite": false,
                    "login": {
                        "username": "userB",
                        "password": "passB",
                        "totp": null,
                        "uris": [{"uri": "https://b.com", "match": null}],
                        "fido2Credentials": []
                    }
                }
            ]
        }
        """

        let creds = try BitwardenJSONParser.parse(json: json)
        #expect(creds.count == 2)
        #expect(creds[0].username == "userA")
        #expect(creds[1].username == "userB")
    }

    // MARK: - Data Parser

    @Test("Parse from Data works same as from String")
    func testParseFromData() throws {
        let data = Data(Self.minimalExport.utf8)
        let creds = try BitwardenJSONParser.parse(data: data)

        #expect(creds.count == 1)
        #expect(creds[0].username == "user@example.com")
    }

    // MARK: - Login with Both Password and Passkey

    @Test("Login with both password and passkey extracts both")
    func testPasswordAndPasskey() throws {
        let json = """
        {
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "id": "both",
                    "folderId": null,
                    "type": 1,
                    "name": "Both Methods",
                    "notes": null,
                    "favorite": false,
                    "login": {
                        "username": "user",
                        "password": "my-password",
                        "totp": null,
                        "uris": [{"uri": "https://both.com", "match": null}],
                        "fido2Credentials": [
                            {
                                "credentialId": "Y3JlZA==",
                                "keyType": "public-key",
                                "keyAlgorithm": "ECDSA",
                                "keyCurve": "P-256",
                                "keyValue": "TUVT",
                                "rpId": "both.com",
                                "rpName": "Both",
                                "userHandle": "aGFuZGxl",
                                "userName": "user",
                                "userDisplayName": "User",
                                "counter": "5",
                                "discoverable": "true",
                                "creationDate": "2025-06-01T00:00:00.000Z"
                            }
                        ]
                    }
                }
            ]
        }
        """

        let creds = try BitwardenJSONParser.parse(json: json)

        #expect(creds.count == 1)
        let cred = creds[0]
        #expect(cred.password == "my-password")
        #expect(cred.extras[PasskeyExtrasKey.rpId] == "both.com")
        #expect(cred.extras[PasskeyExtrasKey.credentialId] == "Y3JlZA==")
    }
}
