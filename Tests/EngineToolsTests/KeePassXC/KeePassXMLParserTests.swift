// Tests for KeePassXMLParser: XML parsing, KPEX passkey extraction,
// recycle bin filtering, toBoxItem() mapping, and hasPasskey.

import Testing
import FlowEngine
@testable import FlowEngine
@testable import EngineTools

@Suite("KeePassXMLParser")
struct KeePassXMLParserTests {

    // MARK: - Basic Parsing

    @Test("Parses a single entry with standard fields")
    func testSingleEntry() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>abc123</UUID>
                        <String><Key>Title</Key><Value>GitHub</Value></String>
                        <String><Key>URL</Key><Value>https://github.com</Value></String>
                        <String><Key>UserName</Key><Value>octocat</Value></String>
                        <String><Key>Password</Key><Value>secret123</Value></String>
                        <String><Key>Notes</Key><Value>My GitHub account</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.title == "GitHub")
        #expect(entry.url == "https://github.com")
        #expect(entry.username == "octocat")
        #expect(entry.password == "secret123")
        #expect(entry.notes == "My GitHub account")
        #expect(entry.uuid == "abc123")
        #expect(entry.groupPath == "Root")
    }

    @Test("Parses multiple entries")
    func testMultipleEntries() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>id1</UUID>
                        <String><Key>Title</Key><Value>Site A</Value></String>
                        <String><Key>URL</Key><Value>https://a.com</Value></String>
                        <String><Key>UserName</Key><Value>userA</Value></String>
                        <String><Key>Password</Key><Value>passA</Value></String>
                    </Entry>
                    <Entry>
                        <UUID>id2</UUID>
                        <String><Key>Title</Key><Value>Site B</Value></String>
                        <String><Key>URL</Key><Value>https://b.com</Value></String>
                        <String><Key>UserName</Key><Value>userB</Value></String>
                        <String><Key>Password</Key><Value>passB</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 2)
        #expect(entries[0].title == "Site A")
        #expect(entries[1].title == "Site B")
    }

    @Test("Parses entry with empty/missing optional fields")
    func testEmptyFields() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>id1</UUID>
                        <String><Key>Title</Key><Value></Value></String>
                        <String><Key>URL</Key><Value></Value></String>
                        <String><Key>UserName</Key><Value></Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].title == "")
        #expect(entries[0].url == "")
        #expect(entries[0].username == "")
        #expect(entries[0].password == nil)
        #expect(entries[0].notes == nil)
    }

    @Test("Returns empty array for empty database")
    func testEmptyDatabase() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)
        #expect(entries.isEmpty)
    }

    @Test("Throws on invalid XML")
    func testInvalidXML() throws {
        let xml = "this is not xml at all <<<<>>>"
        let parser = KeePassXMLParser()
        #expect(throws: KeePassError.self) {
            try parser.parse(xml: xml)
        }
    }

    // MARK: - Nested Groups

    @Test("Tracks nested group path")
    func testNestedGroupPath() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Group>
                        <Name>Passwords</Name>
                        <Group>
                            <Name>Work</Name>
                            <Entry>
                                <UUID>deep</UUID>
                                <String><Key>Title</Key><Value>Deep Entry</Value></String>
                                <String><Key>URL</Key><Value>https://deep.com</Value></String>
                                <String><Key>UserName</Key><Value>deep_user</Value></String>
                            </Entry>
                        </Group>
                    </Group>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].groupPath == "Root/Passwords/Work")
    }

    // MARK: - Recycle Bin Filtering

    @Test("Filters out entries in Recycle Bin group")
    func testRecycleBinFiltering() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>keep</UUID>
                        <String><Key>Title</Key><Value>Keep Me</Value></String>
                        <String><Key>URL</Key><Value>https://keep.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                    </Entry>
                    <Group>
                        <Name>Recycle Bin</Name>
                        <Entry>
                            <UUID>deleted</UUID>
                            <String><Key>Title</Key><Value>Deleted Entry</Value></String>
                            <String><Key>URL</Key><Value>https://deleted.com</Value></String>
                            <String><Key>UserName</Key><Value>deleted_user</Value></String>
                        </Entry>
                    </Group>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].title == "Keep Me")
    }

    @Test("Filters out entries in Trash group")
    func testTrashFiltering() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>keep</UUID>
                        <String><Key>Title</Key><Value>Keep Me</Value></String>
                        <String><Key>URL</Key><Value>https://keep.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                    </Entry>
                    <Group>
                        <Name>Trash</Name>
                        <Entry>
                            <UUID>trashed</UUID>
                            <String><Key>Title</Key><Value>Trashed</Value></String>
                            <String><Key>URL</Key><Value>https://trash.com</Value></String>
                            <String><Key>UserName</Key><Value>trash_user</Value></String>
                        </Entry>
                    </Group>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].title == "Keep Me")
    }

    // MARK: - KPEX Passkey Attributes

    @Test("Parses KPEX passkey custom fields")
    func testKPEXPasskeyExtraction() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>pk1</UUID>
                        <String><Key>Title</Key><Value>Passkey Site</Value></String>
                        <String><Key>URL</Key><Value>https://passkey.example.com</Value></String>
                        <String><Key>UserName</Key><Value>pkuser</Value></String>
                        <String><Key>Password</Key><Value></Value></String>
                        <String><Key>KPEX_PASSKEY_CREDENTIAL_ID</Key><Value>dGVzdC1jcmVk</Value></String>
                        <String><Key>KPEX_PASSKEY_PRIVATE_KEY_PEM</Key><Value>-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG...</Value></String>
                        <String><Key>KPEX_PASSKEY_RELYING_PARTY</Key><Value>passkey.example.com</Value></String>
                        <String><Key>KPEX_PASSKEY_USERNAME</Key><Value>pkuser</Value></String>
                        <String><Key>KPEX_PASSKEY_USER_HANDLE</Key><Value>dXNlcl9oYW5kbGU</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.hasPasskey)
        #expect(entry.customFields[KPEXKey.relyingParty] == "passkey.example.com")
        #expect(entry.customFields[KPEXKey.credentialID] == "dGVzdC1jcmVk")
        #expect(entry.customFields[KPEXKey.username] == "pkuser")
        #expect(entry.customFields[KPEXKey.userHandle] == "dXNlcl9oYW5kbGU")
        #expect(entry.customFields[KPEXKey.privateKeyPEM]?.hasPrefix("-----BEGIN PRIVATE KEY-----") == true)
    }

    @Test("hasPasskey is false for regular entries")
    func testHasPasskeyFalse() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>reg</UUID>
                        <String><Key>Title</Key><Value>Regular</Value></String>
                        <String><Key>URL</Key><Value>https://regular.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                        <String><Key>Password</Key><Value>pass</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(!entries[0].hasPasskey)
    }

    // MARK: - Custom Fields

    @Test("Preserves non-KPEX custom fields")
    func testCustomFields() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>cust</UUID>
                        <String><Key>Title</Key><Value>Custom</Value></String>
                        <String><Key>URL</Key><Value>https://custom.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                        <String><Key>MyCustomField</Key><Value>custom_value</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].customFields["MyCustomField"] == "custom_value")
    }

    // MARK: - TOTP

    @Test("Parses TOTP otp field")
    func testTOTPField() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>otp1</UUID>
                        <String><Key>Title</Key><Value>OTP Site</Value></String>
                        <String><Key>URL</Key><Value>https://otp.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                        <String><Key>otp</Key><Value>otpauth://totp/user@otp.com?secret=BASE32SECRET</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].customFields["otp"] == "otpauth://totp/user@otp.com?secret=BASE32SECRET")
    }

    // MARK: - Tags

    @Test("Parses entry tags")
    func testTags() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>tagged</UUID>
                        <String><Key>Title</Key><Value>Tagged Entry</Value></String>
                        <String><Key>URL</Key><Value>https://tagged.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                        <Tags><Tag>work</Tag><Tag>important</Tag></Tags>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].tags.contains("work"))
        #expect(entries[0].tags.contains("important"))
    }

    // MARK: - toBoxItem()

    @Test("toBoxItem maps standard fields correctly")
    func testToBoxItemStandard() throws {
        let entry = KeePassParsedEntry(
            title: "Test",
            url: "https://test.com",
            username: "testuser",
            password: "testpass",
            notes: "Test notes",
            uuid: "uuid1",
            groupPath: "Root/Work",
            customFields: [:],
            tags: ["tag1", "tag2"]
        )

        let cred = entry.toBoxItem()
        #expect(cred.url == "https://test.com")
        #expect(cred.username == "testuser")
        #expect(cred.password == "testpass")
        #expect(cred.extras["notes"] == "Test notes")
        #expect(cred.extras["group"] == "Root/Work")
        #expect(cred.extras["tags"] == "tag1,tag2")
    }

    @Test("toBoxItem maps KPEX passkey attributes to extras")
    func testToBoxItemPasskey() throws {
        let entry = KeePassParsedEntry(
            title: "Passkey Site",
            url: "https://passkey.com",
            username: "pkuser",
            password: nil,
            notes: nil,
            uuid: "pk1",
            groupPath: "Root",
            customFields: [
                KPEXKey.relyingParty: "passkey.com",
                KPEXKey.credentialID: "dGVzdC1jcmVk",        // Base64Url
                KPEXKey.userHandle: "dXNlcl9oYW5kbGU",      // Base64Url
                KPEXKey.privateKeyPEM: "-----BEGIN PRIVATE KEY-----\ntest",
                KPEXKey.username: "pkuser",
            ],
            tags: []
        )

        let cred = entry.toBoxItem()
        #expect(cred.extras[PasskeyExtrasKey.rpId] == "passkey.com")
        #expect(cred.extras[PasskeyExtrasKey.credentialId] == Base64Url.toBase64("dGVzdC1jcmVk"))
        #expect(cred.extras[PasskeyExtrasKey.userHandle] == Base64Url.toBase64("dXNlcl9oYW5kbGU"))
        #expect(cred.extras[PasskeyExtrasKey.privateKeyPEM] == "-----BEGIN PRIVATE KEY-----\ntest")
        #expect(cred.extras[PasskeyExtrasKey.username] == "pkuser")
    }

    @Test("toBoxItem maps TOTP fields to extras")
    func testToBoxItemTOTP() throws {
        let entry = KeePassParsedEntry(
            title: "TOTP Site",
            url: "https://totp.com",
            username: "user",
            password: "pass",
            notes: nil,
            uuid: "totp1",
            groupPath: "Root",
            customFields: [
                "otp": "otpauth://totp/user?secret=SECRET",
                "TOTP Settings": "30;6",
            ],
            tags: []
        )

        let cred = entry.toBoxItem()
        #expect(cred.extras["otpAuth"] == "otpauth://totp/user?secret=SECRET")
        #expect(cred.extras["otpSettings"] == "30;6")
    }

    @Test("toBoxItem maps remaining custom fields with custom_ prefix")
    func testToBoxItemCustomPrefix() throws {
        let entry = KeePassParsedEntry(
            title: "Custom",
            url: "https://custom.com",
            username: "user",
            password: "pass",
            notes: nil,
            uuid: "c1",
            groupPath: "Root",
            customFields: ["MyField": "MyValue"],
            tags: []
        )

        let cred = entry.toBoxItem()
        #expect(cred.extras["custom_MyField"] == "MyValue")
    }

    // MARK: - Special Characters

    @Test("Handles XML special characters in values")
    func testSpecialCharacters() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>spec</UUID>
                        <String><Key>Title</Key><Value>Site &amp; Co</Value></String>
                        <String><Key>URL</Key><Value>https://site.com/path?a=1&amp;b=2</Value></String>
                        <String><Key>UserName</Key><Value>user&lt;1&gt;</Value></String>
                        <String><Key>Password</Key><Value>&quot;pass&apos;word&quot;</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].title == "Site & Co")
        #expect(entries[0].url == "https://site.com/path?a=1&b=2")
        #expect(entries[0].username == "user<1>")
        #expect(entries[0].password == "\"pass'word\"")
    }

    // MARK: - DeletedObjects

    @Test("Ignores entries in DeletedObjects section")
    func testDeletedObjectsIgnored() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>keep</UUID>
                        <String><Key>Title</Key><Value>Keep</Value></String>
                        <String><Key>URL</Key><Value>https://keep.com</Value></String>
                        <String><Key>UserName</Key><Value>user</Value></String>
                    </Entry>
                </Group>
            </Root>
            <DeletedObjects>
                <DeletedObject>
                    <UUID>deleted-uuid</UUID>
                </DeletedObject>
            </DeletedObjects>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        #expect(entries[0].title == "Keep")
    }

    // MARK: - History

    @Test("Ignores past versions in <History>, emits only the live entry")
    func testHistoryBlockIgnored() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>live</UUID>
                        <String><Key>Title</Key><Value>Live Title</Value></String>
                        <String><Key>URL</Key><Value>https://live.com</Value></String>
                        <String><Key>UserName</Key><Value>liveuser</Value></String>
                        <String><Key>Password</Key><Value>livepass</Value></String>
                        <History>
                            <Entry>
                                <UUID>old1</UUID>
                                <String><Key>Title</Key><Value>Old Title 1</Value></String>
                                <String><Key>URL</Key><Value>https://old1.com</Value></String>
                                <String><Key>UserName</Key><Value>olduser1</Value></String>
                                <String><Key>Password</Key><Value>oldpass1</Value></String>
                            </Entry>
                            <Entry>
                                <UUID>old2</UUID>
                                <String><Key>Title</Key><Value>Old Title 2</Value></String>
                                <String><Key>URL</Key><Value>https://old2.com</Value></String>
                                <String><Key>UserName</Key><Value>olduser2</Value></String>
                                <String><Key>Password</Key><Value>oldpass2</Value></String>
                            </Entry>
                        </History>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.uuid == "live")
        #expect(entry.title == "Live Title")
        #expect(entry.url == "https://live.com")
        #expect(entry.username == "liveuser")
        #expect(entry.password == "livepass")
    }

    @Test("Multiple live entries each with history are all emitted once")
    func testMultipleEntriesWithHistory() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>a</UUID>
                        <String><Key>Title</Key><Value>A</Value></String>
                        <String><Key>URL</Key><Value>https://a.com</Value></String>
                        <String><Key>UserName</Key><Value>ua</Value></String>
                        <String><Key>Password</Key><Value>pa</Value></String>
                        <History>
                            <Entry><UUID>a1</UUID><String><Key>Password</Key><Value>old1</Value></String></Entry>
                            <Entry><UUID>a2</UUID><String><Key>Password</Key><Value>old2</Value></String></Entry>
                            <Entry><UUID>a3</UUID><String><Key>Password</Key><Value>old3</Value></String></Entry>
                        </History>
                    </Entry>
                    <Entry>
                        <UUID>b</UUID>
                        <String><Key>Title</Key><Value>B</Value></String>
                        <String><Key>URL</Key><Value>https://b.com</Value></String>
                        <String><Key>UserName</Key><Value>ub</Value></String>
                        <String><Key>Password</Key><Value>pb</Value></String>
                        <History>
                            <Entry><UUID>b1</UUID><String><Key>Password</Key><Value>old1</Value></String></Entry>
                            <Entry><UUID>b2</UUID><String><Key>Password</Key><Value>old2</Value></String></Entry>
                            <Entry><UUID>b3</UUID><String><Key>Password</Key><Value>old3</Value></String></Entry>
                        </History>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()
        let entries = try parser.parse(xml: xml)

        #expect(entries.count == 2)
        #expect(entries[0].title == "A")
        #expect(entries[0].password == "pa")
        #expect(entries[1].title == "B")
        #expect(entries[1].password == "pb")
    }

    // MARK: - Parser Reuse

    @Test("Parser can be reused for multiple parses")
    func testParserReuse() throws {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>a</UUID>
                        <String><Key>Title</Key><Value>Entry A</Value></String>
                        <String><Key>URL</Key><Value>https://a.com</Value></String>
                        <String><Key>UserName</Key><Value>userA</Value></String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>
        """

        let parser = KeePassXMLParser()

        let first = try parser.parse(xml: xml)
        #expect(first.count == 1)

        let second = try parser.parse(xml: xml)
        #expect(second.count == 1)
    }
}
