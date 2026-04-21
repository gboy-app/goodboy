// Display name and category resolution for devices.

import Foundation

public enum DeviceDisplayName {

    public static func compute(
        tool: String,
        slug: String,
        deviceName: String?,
        config: [String: String]
    ) -> (title: String, subtitle: String?) {

        switch tool {
        case "chrome":
            return chromeDisplayName(slug: slug, deviceName: deviceName, config: config)
        case "keepasscli":
            let dbPath = config["dbPath"] ?? ""
            let filename = (dbPath as NSString).lastPathComponent
            return ("KeePass CLI", filename.isEmpty ? nil : filename)
        case "bitwarden":
            return ("Bitwarden", nil)
        case "onepassword":
            return ("1Password", nil)
        case "protonpass":
            return ("ProtonPass", nil)
        case "icloud":
            return ("iCloud", nil)
        case "json":
            return ("JSON Export", nil)
        default:
            return (tool.capitalized, nil)
        }
    }

    public static func category(tool: String) -> String {
        switch tool {
        case "icloud", "chrome":
            return "browsers"
        case "json":
            return "files"
        default:
            return "cli"
        }
    }

    // MARK: - Private

    private static func chromeDisplayName(
        slug: String,
        deviceName: String?,
        config: [String: String]
    ) -> (title: String, subtitle: String?) {
        switch slug {
        case "brave":   return ("Brave", nil)
        case "edge":    return ("Edge", nil)
        case "opera":   return ("Opera", nil)
        case "arc":     return ("Arc", nil)
        case "vivaldi": return ("Vivaldi", nil)
        default:
            if let name = deviceName, let email = extractParenContent(from: name) {
                return ("Chrome", email)
            }
            return ("Chrome", config["profile"])
        }
    }

    private static func extractParenContent(from string: String) -> String? {
        guard let open = string.firstIndex(of: "("),
              let close = string.lastIndex(of: ")"),
              open < close else { return nil }
        let start = string.index(after: open)
        return String(string[start..<close])
    }
}
