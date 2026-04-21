import Foundation
import MCP
import FlowEngine

/// Construct a `.text` content item without deprecated `metadata:` parameter.
func mcpText(_ string: String) -> MCP.Tool.Content {
    .text(text: string, annotations: nil, _meta: nil)
}

func jsonString(_ value: [String: Any]) -> String {
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
          let string = String(data: data, encoding: .utf8) else {
        return "{\"error\":\"JSON serialization failed\"}"
    }
    return string
}

func jsonString(_ value: [Any]) -> String {
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
          let string = String(data: data, encoding: .utf8) else {
        return "[]"
    }
    return string
}

/// ISO-8601 string with Z suffix for MCP JSON output (e.g. "2026-04-20T04:40:41Z").
func iso8601(_ date: Date) -> String {
    date.formatted(.iso8601)
}

/// Convert DeviceError to [String: Any] for JSONSerialization.
func errorDict(_ error: DeviceError) -> [String: Any] {
    var d: [String: Any] = [
        "category": error.category.rawValue,
        "message": error.message,
    ]
    if let action = error.action { d["action"] = action }
    d["actionURL"] = error.actionURL as Any? ?? NSNull()
    return d
}
