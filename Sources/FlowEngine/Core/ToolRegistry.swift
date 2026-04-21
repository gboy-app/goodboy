import Foundation

// MARK: - Tool Registry

/// Discovers, tracks, and provides access to Tools.
@MainActor
public final class ToolRegistry: ObservableObject {
    public static let shared = ToolRegistry()

    /// All registered Tools (manifest only)
    @Published public private(set) var manifests: [ToolManifest] = []

    /// Live Tool instances (lazy loaded)
    private var toolInstances: [String: any Tool] = [:]

    /// Bundled Tools (compiled into app)
    private var bundledTools: [any Tool.Type] = []

    public init() {}

    // MARK: - Registration

    /// Register bundled Tools (call at app startup)
    public func registerBundled(_ tools: [any Tool.Type]) {
        bundledTools = tools
        refresh()
    }

    /// Refresh registry
    public func refresh() {
        toolInstances.removeAll()
        var newManifests: [ToolManifest] = []

        for toolType in bundledTools {
            let manifest = ToolManifest(from: toolType, bundled: true)
            newManifests.append(manifest)
        }

        let externalManifests = discoverExternalTools()
        newManifests.append(contentsOf: externalManifests)

        manifests = newManifests
    }

    // MARK: - External Tool Discovery

    private func discoverExternalTools() -> [ToolManifest] {
        let toolsDir = AppPaths.externalTools

        guard FileManager.default.fileExists(atPath: toolsDir.path) else {
            return []
        }

        var manifests: [ToolManifest] = []

        do {
            let contents = try FileManager.default.contentsOfDirectory(at: toolsDir, includingPropertiesForKeys: nil)
            for item in contents {
                let manifestPath = item.appendingPathComponent("manifest.json")
                if let data = try? Data(contentsOf: manifestPath),
                   let manifest = try? JSONDecoder().decode(ToolManifest.self, from: data) {
                    manifests.append(manifest)
                }
            }
        } catch {
            print("[ToolRegistry] Error discovering external Tools: \(error)")
        }

        return manifests
    }

    // MARK: - Tool Access

    /// Get a Tool instance by ID
    public func getTool(id: String) -> (any Tool)? {
        if let tool = toolInstances[id] {
            return tool
        }

        guard manifests.contains(where: { $0.id == id }) else {
            return nil
        }

        if let toolType = bundledTools.first(where: { $0.id == id }) {
            let instance = toolType.init()
            toolInstances[id] = instance
            return instance
        }

        return nil
    }

    /// Create a bare Tool instance by ID.
    public func instantiate(id: String) -> (any Tool)? {
        return bundledTools.first(where: { $0.id == id })?.init()
    }

    /// Get all available source Tools
    public func getSourceTools() -> [ToolManifest] {
        manifests.filter { $0.canBeSource }
    }

    /// Get all available destination Tools
    public func getDestTools() -> [ToolManifest] {
        manifests.filter { $0.canBeDestination }
    }

    /// Get valid flows (source -> dest pairs)
    public func getValidFlows() -> [(source: ToolManifest, dest: ToolManifest)] {
        let sources = getSourceTools()
        let dests = getDestTools()

        var flows: [(ToolManifest, ToolManifest)] = []

        for source in sources {
            for dest in dests where source.id != dest.id {
                let commonTypes = Set(source.supportedTypes).intersection(Set(dest.supportedTypes))
                if !commonTypes.isEmpty {
                    flows.append((source, dest))
                }
            }
        }

        return flows
    }
}
