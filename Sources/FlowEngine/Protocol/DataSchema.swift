// How the engine knows what shape of data a tool produces or
// accepts, and how it reports what transfers vs. what is lost when
// one tool's output is about to become another's input.

import Foundation

/// A single BoxItem field that a tool produces (source) or
/// accepts (dest). Enables the hub to know what shape of data is
/// flowing through.
public struct DataSchemaField: Codable, Sendable {
    /// BoxItem field key: "url", "username", "password", "otpAuth", "notes", etc.
    public let key: String
    /// Rendering hint: "url" (linkify), "string" (plain), "secret" (mask).
    public let type: String
    /// Source: always produces this field. Dest: requires this field.
    public let required: Bool

    public init(key: String, type: String, required: Bool) {
        self.key = key
        self.type = type
        self.required = required
    }
}

/// Result of mapping a BoxItem's source schema to a destination
/// schema. The black-box output: what transfers, what's lost.
public struct MappingResult: Sendable {
    /// Field keys both source and dest support — these transfer.
    public let transfers: Set<String>
    /// Field keys the source has but the dest doesn't accept — dropped.
    public let lost: Set<String>
    /// Items that will be skipped (e.g. dest requires password but item has none).
    public let skipReason: String?

    public var isLossy: Bool { !lost.isEmpty }
    public var isFullTransfer: Bool { lost.isEmpty && skipReason == nil }
}

/// Pre-flight report for a dest: what happens to every item group
/// before data moves.
public struct PreflightReport: Sendable {
    public let groups: [PreflightGroup]
    /// Total items that will transfer.
    public var transferCount: Int { groups.reduce(0) { $0 + $1.transferCount } }
    /// Total items that will be skipped.
    public var skipCount: Int { groups.reduce(0) { $0 + $1.skipCount } }
}

/// One source group in the pre-flight report.
public struct PreflightGroup: Sendable {
    /// The sourceDeviceId for all items in this group (nil = unknown source).
    public let sourceDeviceId: String?
    /// Number of items from this source.
    public let itemCount: Int
    /// Schema mapping result for this source→dest pair.
    public let mapping: MappingResult
    /// Number of items that will transfer (passed dest validation).
    public let transferCount: Int
    /// Number of items skipped (failed dest validation).
    public let skipCount: Int
    /// Human-readable skip reasons (e.g. "12 items have no password").
    public let skipReasons: [String]
}
