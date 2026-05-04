// Tests for DiscoveryService.matchSuggestions — the bipartite 1:1
// matcher that pairs existing device rows with tool suggestions.
//
// Regression coverage for the v0.3.0 bug where duplicate suggestions
// (Chromium siblings sharing a chromeDir) caused new device rows to be
// minted on every launch and prevented stale removal.
//
// Run: swift test --filter DiscoveryServiceTests

import Foundation
import Testing
@testable import FlowEngine

@Suite("DiscoveryService.matchSuggestions")
@MainActor
struct DiscoveryServiceMatchTests {

    // MARK: - Single-suggestion happy path

    @Test("Single device + single matching suggestion → claims it")
    func singleMatch() {
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["default"],
            deviceConfigs: [["profile": "Default"]],
            suggestions: [["profile": "Default", "_slug": "default", "_name": "Chrome"]]
        )
        #expect(result == [0])
    }

    @Test("Single device + zero matching suggestions → nil (stale)")
    func staleDevice() {
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["default"],
            deviceConfigs: [["profile": "Default"]],
            suggestions: [["profile": "OtherProfile", "_slug": "secondary"]]
        )
        #expect(result == [nil])
    }

    @Test("Zero devices + N suggestions → empty result")
    func noDevices() {
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: [],
            deviceConfigs: [],
            suggestions: [["profile": "Default"]]
        )
        #expect(result.isEmpty)
    }

    // MARK: - The Chromium-sibling regression

    @Test("Duplicate-config suggestions: each existing device claims one")
    func duplicateConfigSuggestions_oneDeviceEach() {
        // Brave + Vivaldi both suggested as separate brands but their identity
        // configs are identical (both point at the same Brave userDataDir +
        // Default profile, since Vivaldi isn't actually installed and the
        // suggester falls back to the first available Chromium dir).
        let braveDir = "/Users/x/Library/Application Support/BraveSoftware/Brave-Browser"
        let suggestions: [[String: String]] = [
            ["profile": "Default", "chromeDir": braveDir, "_slug": "brave",   "_name": "Brave"],
            ["profile": "Default", "chromeDir": braveDir, "_slug": "vivaldi", "_name": "Vivaldi"],
        ]

        // Two existing devices, one for each brand.
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["brave", "vivaldi"],
            deviceConfigs: [
                ["profile": "Default", "chromeDir": braveDir],
                ["profile": "Default", "chromeDir": braveDir],
            ],
            suggestions: suggestions
        )

        // Both must claim their slug-affine suggestion. Pre-fix, both claimed
        // suggestion 0 because firstIndex(where:) didn't reserve.
        #expect(result == [0, 1])
    }

    @Test("Slug affinity beats lower-index match")
    func slugAffinityWins() {
        // Three suggestions all with the same identity config; slugs are
        // brave, vivaldi, opera. An existing device with slug=vivaldi must
        // claim suggestion 1 (vivaldi) rather than the lowest-index 0 (brave).
        let dir = "/x/Brave"
        let suggestions: [[String: String]] = [
            ["chromeDir": dir, "_slug": "brave"],
            ["chromeDir": dir, "_slug": "vivaldi"],
            ["chromeDir": dir, "_slug": "opera"],
        ]
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["vivaldi"],
            deviceConfigs: [["chromeDir": dir]],
            suggestions: suggestions
        )
        #expect(result == [1])
    }

    @Test("Excess duplicate-config devices fall through to stale (nil)")
    func excessDevicesAreStale() {
        // Eight existing devices all pointing at Brave/Default, but only two
        // brand suggestions exist (Brave + Vivaldi). Six duplicates must be
        // marked stale (nil) so discover() deletes them. This is the AppDB
        // shape we observed in the wild: chrome-brave/-quaternary/-vivaldi
        // plus chrome-default-2/-4/-6/-8/-10 all keying off the same Brave
        // dir; only 2 should survive after the fix.
        let braveDir = "/x/Brave"
        let suggestions: [[String: String]] = [
            ["chromeDir": braveDir, "profile": "Default", "_slug": "brave",   "_name": "Brave"],
            ["chromeDir": braveDir, "profile": "Default", "_slug": "vivaldi", "_name": "Vivaldi"],
        ]
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: [
                "brave", "vivaldi", "quaternary",
                "default-2", "default-4", "default-6", "default-8", "default-10",
            ],
            deviceConfigs: Array(
                repeating: ["chromeDir": braveDir, "profile": "Default"],
                count: 8
            ),
            suggestions: suggestions
        )
        // brave + vivaldi survive (slug-affine); the rest fall through.
        #expect(result == [0, 1, nil, nil, nil, nil, nil, nil])
    }

    @Test("Slug-affine device claims its suggestion even when ordered last")
    func slugAffinityNotOrderDependent() {
        // Existing devices: ["brave", "vivaldi"] processed in order.
        // brave processes first and is slug-affine for suggestion 0.
        // vivaldi must then claim suggestion 1 (slug-affine), not be left
        // stale because suggestion 0 is already covered.
        let dir = "/x/Brave"
        let suggestions: [[String: String]] = [
            ["chromeDir": dir, "_slug": "brave"],
            ["chromeDir": dir, "_slug": "vivaldi"],
        ]
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["brave", "vivaldi"],
            deviceConfigs: [["chromeDir": dir], ["chromeDir": dir]],
            suggestions: suggestions
        )
        #expect(result == [0, 1])
    }

    // MARK: - Identity-key behavior

    @Test("Underscore-prefixed suggestion keys are excluded from identity match")
    func underscoreKeysIgnored() {
        // Suggestion has _name="Chrome" but device config doesn't carry _name.
        // Must still match — only non-`_` keys count toward identity.
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["default"],
            deviceConfigs: [["profile": "Default"]],
            suggestions: [["profile": "Default", "_name": "Chrome", "_slug": "default", "_canRead": "true"]]
        )
        #expect(result == [0])
    }

    @Test("Mismatched identity key disqualifies a suggestion")
    func mismatchedIdentityFails() {
        let result = DiscoveryService.matchSuggestions(
            deviceSlugs: ["default"],
            deviceConfigs: [["profile": "Default", "chromeDir": "/a"]],
            suggestions: [["profile": "Default", "chromeDir": "/b", "_slug": "default"]]
        )
        #expect(result == [nil])
    }
}
