// Tests for KeePassXMLGenerator: XML generation, round-trip with parser,
// KPEX passkey field mapping, deterministic UUID, special characters.

import Testing
import Foundation
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("KeePassXMLGenerator")
struct KeePassXMLGeneratorTests {

    // MARK: - Basic Generation

    @Test("Generates valid XML for a single password credential")
    func testSinglePasswordCredential() throws {
        let cred = BoxItem(
            url: "https://example.com",
            username: "user1",
            password: "pass1",
            extras: [:]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])

        #expect(xml.contains("<?xml version=\"1.0\" encoding=\"utf-8\"?>"))
        #expect(xml.contains("<KeePassFile>"))
        #expect(xml.contains("<Generator>Goodboy</Generator>"))
        #expect(xml.contains("<Name>Root</Name>"))
        #expect(xml.contains("<Key>Title</Key><Value>https://example.com</Value>"))
        #expect(xml.contains("<Key>URL</Key><Value>https://example.com</Value>"))
        #expect(xml.contains("<Key>UserName</Key><Value>user1</Value>"))
        #expect(xml.contains("<Key>Password</Key><Value>pass1</Value>"))
        #expect(xml.contains("</KeePassFile>"))
    }

    @Test("Generates XML for empty credentials array")
    func testEmptyCredentials() {
        let xml = KeePassXMLGenerator.generate(credentials: [])
        #expect(xml.contains("<KeePassFile>"))
        #expect(xml.contains("</KeePassFile>"))
        #expect(!xml.contains("<Entry>"))
    }

    @Test("Generates multiple entries")
    func testMultipleEntries() {
        let creds = [
            BoxItem(url: "https://a.com", username: "ua", password: "pa", extras: [:]),
            BoxItem(url: "https://b.com", username: "ub", password: "pb", extras: [:]),
        ]

        let xml = KeePassXMLGenerator.generate(credentials: creds)

        // Count entries
        let entryCount = xml.components(separatedBy: "<Entry>").count - 1
        #expect(entryCount == 2)
    }

    @Test("Uses custom group name")
    func testCustomGroupName() {
        let cred = BoxItem(url: "https://test.com", username: "u", password: "p", extras: [:])
        let xml = KeePassXMLGenerator.generate(credentials: [cred], groupName: "Imported")

        #expect(xml.contains("<Name>Imported</Name>"))
        #expect(!xml.contains("<Name>Root</Name>"))
    }

    @Test("Defaults to Root group name")
    func testDefaultGroupName() {
        let cred = BoxItem(url: "https://test.com", username: "u", password: "p", extras: [:])
        let xml = KeePassXMLGenerator.generate(credentials: [cred])

        #expect(xml.contains("<Name>Root</Name>"))
    }

    // MARK: - Passkey KPEX Attributes

    @Test("Generates KPEX passkey custom fields")
    func testPasskeyFields() {
        let cred = BoxItem(
            url: "https://passkey.example.com",
            username: "pkuser",
            password: nil,
            extras: [
                PasskeyExtrasKey.rpId: "passkey.example.com",
                PasskeyExtrasKey.credentialId: "dGVzdC1jcmVk",   // standard Base64
                PasskeyExtrasKey.userHandle: "dXNlcl9oYW5kbGU=", // standard Base64
                PasskeyExtrasKey.privateKeyPEM: "-----BEGIN PRIVATE KEY-----\nMIGH...",
                PasskeyExtrasKey.username: "pkuser",
            ]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])

        #expect(xml.contains("<Key>KPEX_PASSKEY_RELYING_PARTY</Key><Value>passkey.example.com</Value>"))
        #expect(xml.contains("<Key>KPEX_PASSKEY_USERNAME</Key><Value>pkuser</Value>"))
        #expect(xml.contains("<Key>KPEX_PASSKEY_PRIVATE_KEY_PEM</Key>"))
        // Credential ID should be converted from standard Base64 to Base64Url
        #expect(xml.contains("<Key>KPEX_PASSKEY_CREDENTIAL_ID</Key>"))
        #expect(xml.contains("<Key>KPEX_PASSKEY_USER_HANDLE</Key>"))
    }

    @Test("Converts credential ID from standard Base64 to Base64Url in KPEX output")
    func testBase64UrlConversion() {
        let standardBase64 = "abc+def/ghi="
        let cred = BoxItem(
            url: "https://test.com",
            username: "u",
            password: nil,
            extras: [
                PasskeyExtrasKey.rpId: "test.com",
                PasskeyExtrasKey.credentialId: standardBase64,
            ]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        let expected = Base64Url.fromBase64(standardBase64)  // "abc-def_ghi"
        #expect(xml.contains(expected))
    }

    // MARK: - TOTP

    @Test("Generates TOTP otp field from extras")
    func testTOTPField() {
        let cred = BoxItem(
            url: "https://totp.com",
            username: "user",
            password: "pass",
            extras: ["otpAuth": "otpauth://totp/user?secret=SECRET"]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        #expect(xml.contains("<Key>otp</Key><Value>otpauth://totp/user?secret=SECRET</Value>"))
    }

    // MARK: - Notes and Title from Extras

    @Test("Uses title from extras if present")
    func testTitleFromExtras() {
        let cred = BoxItem(
            url: "https://test.com",
            username: "u",
            password: "p",
            extras: ["title": "My Custom Title"]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        #expect(xml.contains("<Key>Title</Key><Value>My Custom Title</Value>"))
    }

    @Test("Falls back to URL for title when no title in extras")
    func testTitleFallbackToURL() {
        let cred = BoxItem(
            url: "https://fallback.com",
            username: "u",
            password: "p",
            extras: [:]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        #expect(xml.contains("<Key>Title</Key><Value>https://fallback.com</Value>"))
    }

    @Test("Includes notes from extras")
    func testNotes() {
        let cred = BoxItem(
            url: "https://notes.com",
            username: "u",
            password: "p",
            extras: ["notes": "Important note"]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        #expect(xml.contains("<Key>Notes</Key><Value>Important note</Value>"))
    }

    // MARK: - Special Characters (XML Escaping)

    @Test("Escapes XML special characters in values")
    func testXMLEscaping() {
        let cred = BoxItem(
            url: "https://test.com/path?a=1&b=2",
            username: "user<>\"'",
            password: "p&ss<w>rd",
            extras: [:]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        #expect(xml.contains("&amp;"))
        #expect(xml.contains("&lt;"))
        #expect(xml.contains("&gt;"))
        #expect(!xml.contains("<w>"))  // Should be escaped
    }

    @Test("Escapes group name")
    func testGroupNameEscaping() {
        let cred = BoxItem(url: "https://test.com", username: "u", password: "p", extras: [:])
        let xml = KeePassXMLGenerator.generate(credentials: [cred], groupName: "Work & Personal")

        #expect(xml.contains("<Name>Work &amp; Personal</Name>"))
    }

    // MARK: - Deterministic UUID

    @Test("Same credentials produce same UUID")
    func testDeterministicUUIDConsistency() {
        let cred = BoxItem(
            url: "https://example.com",
            username: "user",
            password: "pass",
            extras: [PasskeyExtrasKey.rpId: "example.com"]
        )

        let uuid1 = KeePassXMLGenerator.deterministicUUID(for: cred)
        let uuid2 = KeePassXMLGenerator.deterministicUUID(for: cred)
        #expect(uuid1 == uuid2)
    }

    @Test("Different credentials produce different UUIDs")
    func testDeterministicUUIDDifference() {
        let cred1 = BoxItem(url: "https://a.com", username: "u1", password: "p", extras: [:])
        let cred2 = BoxItem(url: "https://b.com", username: "u2", password: "p", extras: [:])

        let uuid1 = KeePassXMLGenerator.deterministicUUID(for: cred1)
        let uuid2 = KeePassXMLGenerator.deterministicUUID(for: cred2)
        #expect(uuid1 != uuid2)
    }

    @Test("UUID is base64-encoded 16 bytes")
    func testUUIDFormat() {
        let cred = BoxItem(url: "https://test.com", username: "u", password: "p", extras: [:])
        let uuid = KeePassXMLGenerator.deterministicUUID(for: cred)

        // Base64 of 16 bytes = 24 chars (with padding)
        let data = Data(base64Encoded: uuid)
        #expect(data != nil)
        #expect(data?.count == 16)
    }

    @Test("Generated XML includes UUID element")
    func testXMLIncludesUUID() {
        let cred = BoxItem(url: "https://test.com", username: "u", password: "p", extras: [:])
        let xml = KeePassXMLGenerator.generate(credentials: [cred])

        #expect(xml.contains("<UUID>"))
        #expect(xml.contains("</UUID>"))
    }

    // MARK: - Round-Trip: Generate → Parse

    @Test("Round-trip: generate XML → parse with KeePassXMLParser → verify fields")
    func testRoundTripStandard() throws {
        let cred = BoxItem(
            url: "https://roundtrip.com",
            username: "rtuser",
            password: "rtpass",
            extras: [
                "notes": "Round-trip test",
                "title": "RT Entry",
            ]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.title == "RT Entry")
        #expect(entry.url == "https://roundtrip.com")
        #expect(entry.username == "rtuser")
        #expect(entry.password == "rtpass")
        #expect(entry.notes == "Round-trip test")
    }

    @Test("Round-trip: passkey KPEX fields survive generate → parse")
    func testRoundTripPasskey() throws {
        let cred = BoxItem(
            url: "https://passkey-rt.com",
            username: "pkuser",
            password: nil,
            extras: [
                PasskeyExtrasKey.rpId: "passkey-rt.com",
                PasskeyExtrasKey.credentialId: "dGVzdENyZWQ=",   // standard Base64
                PasskeyExtrasKey.userHandle: "dXNlckhhbmRsZQ==", // standard Base64
                PasskeyExtrasKey.privateKeyPEM: "-----BEGIN PRIVATE KEY-----\nMIGH...",
                PasskeyExtrasKey.username: "pkuser",
            ]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.hasPasskey)
        #expect(entry.customFields[KPEXKey.relyingParty] == "passkey-rt.com")
        #expect(entry.customFields[KPEXKey.username] == "pkuser")
        #expect(entry.customFields[KPEXKey.privateKeyPEM] == "-----BEGIN PRIVATE KEY-----\nMIGH...")

        // Verify Base64Url conversion in KPEX fields
        let kpexCredId = entry.customFields[KPEXKey.credentialID]
        #expect(kpexCredId != nil)

        // BoxItem round-trip through toBoxItem
        let flowCred = entry.toBoxItem()
        #expect(flowCred.extras[PasskeyExtrasKey.rpId] == "passkey-rt.com")
        #expect(flowCred.extras[PasskeyExtrasKey.username] == "pkuser")
    }

    @Test("Round-trip: multiple entries with mixed types")
    func testRoundTripMixed() throws {
        let creds = [
            BoxItem(
                url: "https://password-only.com",
                username: "user1",
                password: "pass1",
                extras: [:]
            ),
            BoxItem(
                url: "https://passkey-site.com",
                username: "pkuser",
                password: nil,
                extras: [
                    PasskeyExtrasKey.rpId: "passkey-site.com",
                    PasskeyExtrasKey.credentialId: "Y3JlZC1pZA==",
                ]
            ),
        ]

        let xml = KeePassXMLGenerator.generate(credentials: creds)
        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 2)
        #expect(!entries[0].hasPasskey)
        #expect(entries[1].hasPasskey)
    }

    @Test("Round-trip: special characters survive generate → parse")
    func testRoundTripSpecialChars() throws {
        let cred = BoxItem(
            url: "https://test.com/path?a=1&b=2",
            username: "user<special>",
            password: "p&ss\"word",
            extras: ["notes": "Notes with <html> & 'quotes'"]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.url == "https://test.com/path?a=1&b=2")
        #expect(entry.username == "user<special>")
        #expect(entry.password == "p&ss\"word")
        #expect(entry.notes == "Notes with <html> & 'quotes'")
    }

    // MARK: - XML Escape Helper

    @Test("escapeXML handles all five XML special characters")
    func testEscapeXML() {
        let input = "a&b<c>d\"e'f"
        let escaped = KeePassXMLGenerator.escapeXML(input)
        #expect(escaped == "a&amp;b&lt;c&gt;d&quot;e&apos;f")
    }

    @Test("escapeXML leaves plain text unchanged")
    func testEscapeXMLPlainText() {
        let input = "hello world 123"
        #expect(KeePassXMLGenerator.escapeXML(input) == input)
    }

    @Test("escapeXML handles empty string")
    func testEscapeXMLEmpty() {
        #expect(KeePassXMLGenerator.escapeXML("") == "")
    }

    // MARK: - Nil Password

    @Test("Entry without password omits Password element")
    func testNilPasswordOmitted() {
        let cred = BoxItem(
            url: "https://passkey.com",
            username: "user",
            password: nil,
            extras: [PasskeyExtrasKey.rpId: "passkey.com"]
        )

        let xml = KeePassXMLGenerator.generate(credentials: [cred])
        #expect(!xml.contains("<Key>Password</Key>"))
    }
}
