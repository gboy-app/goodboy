// Shared error type for file-based parsers (CSV, JSON, ZIP).

import Foundation
import FlowEngine

public enum FileParseError: Error, LocalizedError {
    case unsupportedFormat(String)
    case encrypted(String)
    case emptyFile(String)
    case invalidStructure(String)
    case unzipFailed(String)
    case noJSONInZip

    public var errorDescription: String? {
        switch self {
        case .unsupportedFormat(let detail):
            return detail
        case .encrypted(let detail):
            return detail
        case .emptyFile(let detail):
            return detail
        case .invalidStructure(let detail):
            return detail
        case .unzipFailed(let detail):
            return detail
        case .noJSONInZip:
            return "No JSON files found in ZIP archive. Ensure the ZIP contains an unencrypted export."
        }
    }
}
