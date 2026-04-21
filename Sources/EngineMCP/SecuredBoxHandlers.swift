// MCP handlers for SecuredBox inspection. `goodboy_securedbox` is always
// available; dump/delete/clear are DEBUG-only (see ToolDefinitions).

import Foundation
import MCP
import FlowEngine

func securedBoxSnapshot() -> [String: Any] {
    let items = SecuredBox.shared.items
    let total = items.count

    guard total > 0 else {
        return [
            "total": 0, "isEmpty": true,
            "types": ["passwords": 0, "withOTP": 0, "passkeys": 0, "usernameOnly": 0],
            "sources": [] as [Any],
            "duplicates": 0,
        ]
    }

    // Type counts
    let passwords = items.filter { $0.password != nil }.count
    let withOTP = items.filter { $0.extras["otpAuth"] != nil }.count
    let passkeys = items.filter { $0.extras["passkey_rpId"] != nil }.count
    let usernameOnly = items.filter { $0.password == nil && $0.extras["passkey_rpId"] == nil }.count

    // Duplicate count: group by (host, username), count groups with >1 entry
    var groups: [String: Int] = [:]
    for item in items {
        let host = URL(string: item.url)?.host ?? item.url
        let key = "\(host)\t\(item.username)"
        groups[key, default: 0] += 1
    }
    let duplicates = groups.values.filter { $0 > 1 }.count

    return [
        "total": total,
        "isEmpty": false,
        "types": [
            "passwords": passwords,
            "withOTP": withOTP,
            "passkeys": passkeys,
            "usernameOnly": usernameOnly,
        ] as [String: Any],
        "sources": Array(Set(items.compactMap { $0.sourceDeviceId })).sorted(),
        "duplicates": duplicates,
    ]
}

func preflightSnapshot(_ report: PreflightReport) -> [String: Any] {
    var groupDicts: [[String: Any]] = []
    for g in report.groups {
        var dict: [String: Any] = [
            "itemCount": g.itemCount,
            "transferCount": g.transferCount,
            "skipCount": g.skipCount,
            "transfers": g.mapping.transfers.sorted(),
            "lost": g.mapping.lost.sorted(),
        ]
        if let sourceId = g.sourceDeviceId { dict["sourceDeviceId"] = sourceId }
        if !g.skipReasons.isEmpty { dict["skipReasons"] = g.skipReasons }
        if let reason = g.mapping.skipReason { dict["skipReason"] = reason }
        groupDicts.append(dict)
    }
    return [
        "totalTransfer": report.transferCount,
        "totalSkip": report.skipCount,
        "groups": groupDicts,
    ]
}

func handleSecuredBox() -> CallTool.Result {
    return CallTool.Result(content: [mcpText(jsonString(securedBoxSnapshot()))])
}

func handleSecuredBoxDump(_ args: [String: Value]?) -> CallTool.Result {
    let items = SecuredBox.shared.items
    let offset = max(0, args?["offset"].flatMap { val -> Int? in
        if case .int(let n) = val { return n }
        if case .double(let f) = val { return Int(f) }
        return nil
    } ?? 0)
    let limit = args?["limit"].flatMap { val -> Int? in
        if case .int(let n) = val { return n }
        if case .double(let f) = val { return Int(f) }
        return nil
    } ?? 50

    let end = min(offset + limit, items.count)
    let slice = offset < items.count ? Array(items[offset..<end]) : []

    let serialized: [[String: Any]] = slice.enumerated().map { i, item in
        var entry: [String: Any] = [
            "index": offset + i,
            "url": item.url,
            "username": item.username,
        ]
        if let pw = item.password { entry["password"] = pw }
        if !item.extras.isEmpty { entry["extras"] = item.extras }
        if let src = item.sourceDeviceId { entry["sourceDeviceId"] = src }
        return entry
    }

    let result: [String: Any] = [
        "total": items.count,
        "offset": offset,
        "limit": limit,
        "returned": serialized.count,
        "items": serialized,
    ]
    return CallTool.Result(content: [mcpText(jsonString(result))])
}

func handleSecuredBoxClear() -> CallTool.Result {
    let count = SecuredBox.shared.count
    SecuredBox.shared.clear()
    return CallTool.Result(content: [mcpText(jsonString(["cleared": count]))])
}

func handleSecuredBoxDelete(_ args: [String: Value]?) throws -> CallTool.Result {
    guard let indicesValue = args?["indices"],
          case .array(let arr) = indicesValue else {
        throw MCPError.invalidParams("Required: indices (array of integers)")
    }

    let indices = Set(arr.compactMap { val -> Int? in
        if case .int(let n) = val { return n }
        if case .double(let f) = val { return Int(f) }
        return nil
    })

    let items = SecuredBox.shared.items
    guard !indices.isEmpty else {
        throw MCPError.invalidParams("indices array is empty")
    }
    guard indices.allSatisfy({ $0 >= 0 && $0 < items.count }) else {
        throw MCPError.invalidParams("Index out of range (0..<\(items.count))")
    }

    let remaining = items.enumerated().filter { !indices.contains($0.offset) }.map { $0.element }
    SecuredBox.shared.load(remaining)

    var result = securedBoxSnapshot()
    result["deleted"] = indices.count
    return CallTool.Result(content: [mcpText(jsonString(result))])
}
