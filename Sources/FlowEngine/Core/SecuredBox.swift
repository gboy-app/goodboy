// SecuredBox is the in-memory staging area for credential flows.
// BoxItem is a single credential in transit between Tools.

import Foundation
import os.log

// MARK: - BoxItem & SecuredBox

/// A credential in transit between Tools. Not a database record.
/// Standard fields are top-level. Everything else goes in `extras`.
public struct BoxItem: Codable, Sendable {
    public let url: String
    public let username: String
    public let password: String?
    public let extras: [String: String]
    public let sourceDeviceId: String?

    public init(url: String, username: String, password: String?, extras: [String: String] = [:], sourceDeviceId: String? = nil) {
        self.url = url
        self.username = username
        self.password = password
        self.extras = extras
        self.sourceDeviceId = sourceDeviceId
    }
}

// MARK: - BoxItem Self-Awareness (The Black Box)

extension BoxItem {

    /// The set of field keys this item carries.
    /// Includes the 3 core fields (if present) plus all extras keys.
    /// This is what the item *actually has*, regardless of source schema.
    public var presentKeys: Set<String> {
        var keys = Set<String>()
        if !url.isEmpty { keys.insert("url") }
        if !username.isEmpty { keys.insert("username") }
        if password != nil { keys.insert("password") }
        keys.formUnion(extras.keys)
        return keys
    }

    /// Compute mapping result against a destination schema.
    ///
    /// `transfers` and `lost` are reported for the preflight summary ("these
    /// fields land, these get dropped"). `skipReason` is always nil — Goodboy
    /// does not drop items because they're missing a dest-required field. A
    /// password-only record (PIN), a username-only record (passkey handle), a
    /// note-only record (secure note) are all legitimate credentials; the
    /// destination's `execute()` decides how to serialize whatever it's given.
    public func mapping(to destFields: [DataSchemaField]) -> MappingResult {
        let myKeys = presentKeys
        let destKeys = Set(destFields.map(\.key))
        let transfers = myKeys.intersection(destKeys)
        let lost = myKeys.subtracting(destKeys)
        return MappingResult(transfers: transfers, lost: lost, skipReason: nil)
    }

    /// Convenience overload — delegates to the field-based mapping, which no
    /// longer uses `required` for skip decisions.
    public func mapping(to destKeys: Set<String>) -> MappingResult {
        let fields = destKeys.map { DataSchemaField(key: $0, type: "string", required: false) }
        return mapping(to: fields)
    }

    /// Convenience: just the dropped field keys for a given dest.
    public func loss(to destKeys: Set<String>) -> Set<String> {
        presentKeys.subtracting(destKeys)
    }
}

// MARK: - SecuredBox

/// Singleton staging area for credential flows.
/// Writers load credentials in, readers consume them.
public final class SecuredBox: @unchecked Sendable {

    public static let shared = SecuredBox()

    private let log = Logger(subsystem: "app.gboy.goodboy", category: "SecuredBox")

    private var _items: [BoxItem] = []
    private let lock = NSLock()

    public var items: [BoxItem] {
        lock.lock()
        defer { lock.unlock() }
        return _items
    }

    private init() {}

    /// For testing: create an isolated store
    public init(forTesting: Bool) {}

    /// Writer loads credentials into the store (replaces any previous contents).
    public func load(_ credentials: [BoxItem]) {
        lock.lock()
        defer { lock.unlock() }
        _items = credentials
        log.info("Loaded \(credentials.count) credentials into store")
    }

    /// Append credentials to the store (does not replace).
    public func append(_ credentials: [BoxItem]) {
        lock.lock()
        defer { lock.unlock() }
        _items.append(contentsOf: credentials)
        log.info("Appended \(credentials.count) credentials, total now \(self._items.count)")
    }

    /// Stamp all unstamped items with a source device ID.
    /// Called by FlowEngine after a source execute completes.
    public func stampSource(_ deviceId: String) {
        lock.lock()
        defer { lock.unlock() }
        _items = _items.map { item in
            guard item.sourceDeviceId == nil else { return item }
            return BoxItem(url: item.url, username: item.username, password: item.password,
                           extras: item.extras, sourceDeviceId: deviceId)
        }
    }

    /// Clear all credentials from memory.
    /// Note: Swift strings use copy-on-write and can't be truly zeroed in-place.
    /// We overwrite password fields as defense-in-depth before releasing the array.
    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        let count = _items.count
        // Overwrite password fields before releasing (defense-in-depth)
        for i in _items.indices {
            _items[i] = BoxItem(url: "", username: "", password: nil, extras: [:], sourceDeviceId: nil)
        }
        _items = []
        if count > 0 {
            log.info("Cleared \(count) credentials from store")
        }
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return _items.count
    }

    /// Remove items at the given indices (0-based).
    public func remove(at indices: IndexSet) {
        lock.lock()
        defer { lock.unlock() }
        let sorted = indices.sorted().reversed()
        for i in sorted { _items.remove(at: i) }
    }

    public var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _items.isEmpty
    }

    /// Summary string for the agent — field counts, not credential values.
    public var summary: String {
        lock.lock()
        defer { lock.unlock() }

        guard !_items.isEmpty else { return "Store is empty." }

        let total = _items.count
        let withPassword = _items.filter { $0.password != nil }.count
        let withOTP = _items.filter { $0.extras["otpAuth"] != nil }.count
        let withPasskey = _items.filter { $0.extras["passkey_rpId"] != nil }.count
        let withNotes = _items.filter { $0.extras["notes"] != nil }.count

        var parts = ["\(total) credentials"]
        if withPassword > 0 { parts.append("\(withPassword) passwords") }
        if withOTP > 0 { parts.append("\(withOTP) with OTP") }
        if withPasskey > 0 { parts.append("\(withPasskey) passkeys") }
        if withNotes > 0 { parts.append("\(withNotes) with notes") }

        return parts.joined(separator: ", ")
    }
}
