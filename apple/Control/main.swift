import Foundation
import NetworkExtension
import CoreBridge
import SystemExtensions

func fail(_ message: String) -> Never { fputs("error: \(message)\n", stderr); exit(1) }
let args = CommandLine.arguments
guard args.count >= 2 else { fail("version | activate | deactivate | install <conf> | start | stop | status | events | remove") }
let command = args[1]
let bundle = Bundle.main.bundleIdentifier ?? "org.bimeron.core.dev"
let providerBundle = bundle + ".packet"
if command == "version" {
    if let p = RLVersion() { print(String(cString: p)); RLFree(p) }; exit(0)
}
var activation: SystemActivation?
if command == "activate" || command == "deactivate" {
    guard Bundle.main.object(forInfoDictionaryKey: "RLExtensionKind") as? String == "system-extension" else { fail("activation is only for system-extension builds") }
    let delegate = SystemActivation(); activation = delegate
    let request = command == "activate" ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerBundle, queue: .main) : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: providerBundle, queue: .main)
    request.delegate = delegate; OSSystemExtensionManager.shared.submitRequest(request); dispatchMain()
}

func inlineProfile(_ path: String) throws -> Data {
    let url = URL(fileURLWithPath: path)
    let source = try String(contentsOf: url, encoding: .utf8)
    var inKey = false
    let lines = try source.components(separatedBy: .newlines).map { line -> String in
        let text = line.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("[") { inKey = text == "[AccessKey]" }
        if inKey, let separator = text.firstIndex(of: "="), text[..<separator].trimmingCharacters(in: .whitespaces) == "File" {
            let filename = text[text.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            let keyURL = filename.hasPrefix("/") ? URL(fileURLWithPath: filename) : url.deletingLastPathComponent().appendingPathComponent(filename)
            let key = try String(contentsOf: keyURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !key.contains("\n"), !key.contains("\r") else { throw NSError(domain: "Bimeron", code: 1) }
            return "Key = " + key
        }
        return line
    }
    return Data(lines.joined(separator: "\n").utf8)
}

NETunnelProviderManager.loadAllFromPreferences { managers, error in
    guard error == nil else { fail("cannot read VPN preferences; verify signing and provisioning") }
    let matches = (managers ?? []).filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundle }
    guard matches.count <= 1 else { fail("multiple Bimeron configurations found") }
    let manager = matches.first ?? NETunnelProviderManager()
    switch command {
    case "install":
        guard args.count == 3, manager.connection.status == .disconnected || manager.connection.status == .invalid else { fail("install requires a profile and disconnected session") }
        do {
            let data = try inlineProfile(args[2])
            let h = data.withUnsafeBytes { RLCreate(UnsafeMutableRawPointer(mutating: $0.baseAddress), Int32($0.count)) }
            guard h != 0 else { fail("invalid profile; VPN mode and KillSwitch=false required") }
            _ = RLStop(h)
            let id = UUID().uuidString
            try ProfileStore.write(id, data)
            let previous = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profile_id"] as? String
            let config = NETunnelProviderProtocol()
            config.providerBundleIdentifier = providerBundle; config.serverAddress = "Bimeron"
            config.providerConfiguration = ["profile_id": id]
            manager.protocolConfiguration = config; manager.localizedDescription = "Bimeron Core"; manager.isEnabled = true
            manager.saveToPreferences { error in
                if error != nil { ProfileStore.remove(id); fail("cannot save VPN preferences; verify provisioning") }
                if let old = previous { ProfileStore.remove(old) }
                print("Bimeron Core VPN configuration registered"); exit(0)
            }
        } catch { fail("cannot import profile into shared Keychain") }
    case "start":
        guard !matches.isEmpty else { fail("install a profile first") }
        do {
            guard let session = manager.connection as? NETunnelProviderSession,
                let id = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profile_id"] as? String else { fail("invalid provider configuration") }
            let data = try ProfileStore.read(id)
            try session.startTunnel(options: ["profile_data": data as NSData])
            print("Start requested"); exit(0)
        } catch { fail("VPN start rejected or Keychain profile unavailable") }
    case "stop": manager.connection.stopVPNTunnel(); print("Stop requested"); exit(0)
    case "status", "events":
        print("System VPN status: \(manager.connection.status.rawValue)")
        if let session = manager.connection as? NETunnelProviderSession, session.status == .connected {
            do { try session.sendProviderMessage(Data(command.utf8)) { data in
                if let data = data, let text = String(data: data, encoding: .utf8) { print(text) }; exit(0)
            }} catch { fail("core status unavailable") }
        } else { exit(0) }
    case "remove":
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else { fail("stop VPN before removal") }
        let id = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profile_id"] as? String
        manager.removeFromPreferences { error in
            if error != nil { fail("cannot remove VPN configuration") }
            if let id = id { ProfileStore.remove(id) }; print("Removed"); exit(0)
        }
    default: fail("unknown command")
    }
}
DispatchQueue.main.asyncAfter(deadline: .now() + 15) { fail("system operation timed out") }
dispatchMain()
