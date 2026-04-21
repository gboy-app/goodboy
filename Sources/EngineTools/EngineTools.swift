import FlowEngine

/// Free-tier tools: Bitwarden, KeePassXC, 1Password, ProtonPass, JSON export, Chrome.
/// Shipped in both the app (Mode 1) and the standalone stdio binary (Mode 2).
public func engineTools() -> [any Tool.Type] {
    [
        BitwardenCLITool.self,
        KeePassCLITool.self,
        OnePasswordCLITool.self,
        ProtonPassCLITool.self,
        JSONExportTool.self,
        ChromeTool.self,
    ]
}
