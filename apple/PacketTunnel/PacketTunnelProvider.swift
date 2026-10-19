import Foundation
import Network
import NetworkExtension
import CoreBridge

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lifecycle = DispatchQueue(label: "Bimeron.lifecycle")
    private let output = DispatchQueue(label: "Bimeron.packet-output")
    private let lock = NSLock()
    private var handle: UInt64 = 0
    private var timer: DispatchSourceTimer?
    private var monitor: NWPathMonitor?
    private var pendingStart: ((Error?) -> Void)?
    private func finishStart(_ error: Error?) { let callback = pendingStart; pendingStart = nil; callback?(error) }
    private func current() -> UInt64 { lock.lock(); defer { lock.unlock() }; return handle }
    private func setHandle(_ value: UInt64) { lock.lock(); handle = value; lock.unlock() }
    private func failure(_ code: Int) -> NSError { NSError(domain: "Bimeron", code: code, userInfo: [NSLocalizedDescriptionKey: "Core tunnel startup failed"] ) }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        lifecycle.async {
            guard self.current() == 0 else { completionHandler(self.failure(1)); return }
            self.pendingStart = completionHandler
            do {
                guard self.current() == 0,
                    let config = self.protocolConfiguration as? NETunnelProviderProtocol,
                    let id = config.providerConfiguration?["profile_id"] as? String else { throw self.failure(1) }
                let profile: Data
                if let provided = options?["profile_data"] as? NSData { profile = provided as Data }
                else if Bundle.main.object(forInfoDictionaryKey: "RLExtensionKind") as? String == "system-extension" { throw self.failure(9) }
                else { profile = try ProfileStore.read(id) }
                let h = profile.withUnsafeBytes { RLCreate(UnsafeMutableRawPointer(mutating: $0.baseAddress), Int32($0.count)) }
                guard h != 0 else { throw self.failure(2) }
                self.setHandle(h)
                guard let pointer = RLSettings(h) else { throw self.failure(3) }
                let data = Data(String(cString: pointer).utf8); RLFree(pointer)
                guard let details = try JSONSerialization.jsonObject(with: data) as? [String: Any], let mtu = details["mtu"] as? Int else { throw self.failure(4) }
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.2")
                let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
                ipv4.includedRoutes = [NEIPv4Route.default()]; settings.ipv4Settings = ipv4
                let ipv6 = NEIPv6Settings(addresses: ["fdfe:524c::1"], networkPrefixLengths: [128])
                ipv6.includedRoutes = [NEIPv6Route.default()]; settings.ipv6Settings = ipv6
                let dns = NEDNSSettings(servers: ["198.18.0.2"])
                dns.matchDomains = [""]; dns.matchDomainsNoSearch = true; settings.dnsSettings = dns
                settings.mtu = NSNumber(value: mtu)
                self.setTunnelNetworkSettings(settings) { error in
                    self.lifecycle.async {
                        guard self.current() == h else { return }
                        if let error = error { self.abort(h); self.finishStart(error); return }
                        guard RLStart(h) == 0 else { self.abort(h); self.finishStart(self.failure(5)); return }
                        self.waitForCore(h)
                    }
                }
            } catch { self.abort(self.current()); self.finishStart(error) }
        }
    }
    private func abort(_ h: UInt64) { setHandle(0); if h != 0 { _ = RLStop(h) }; timer?.cancel(); timer = nil }
    private func waitForCore(_ h: UInt64) {
        let deadline = Date().addingTimeInterval(90)
        let t = DispatchSource.makeTimerSource(queue: lifecycle); timer = t
        t.schedule(deadline: .now(), repeating: .milliseconds(200))
        t.setEventHandler { [weak self] in
            guard let self = self, self.current() == h else { return }
            guard let p = RLStatus(h) else { return }
            let data = Data(String(cString: p).utf8); RLFree(p)
            let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            let state = (value?["status"] as? [String: Any])?["State"] as? String
            if state == "connected" {
                self.timer?.cancel(); self.timer = nil
                self.readPackets(h); self.output.async { self.writePackets(h) }
                self.watchPath(h); self.finishStart(nil)
            } else if state == "failed" || Date() > deadline {
                self.abort(h); self.finishStart(self.failure(6))
            }
        }
        t.resume()
    }
    private func readPackets(_ h: UInt64) {
        guard current() == h else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, self.current() == h else { return }
            for packet in packets {
                _ = packet.withUnsafeBytes { RLWritePacket(h, UnsafeMutableRawPointer(mutating: $0.baseAddress), Int32($0.count)) }
            }
            self.readPackets(h)
        }
    }
    private func writePackets(_ h: UInt64) {
        var buffer = [UInt8](repeating: 0, count: 65535)
        while current() == h {
            let count = buffer.withUnsafeMutableBytes { RLReadPacket(h, $0.baseAddress, 65535, 100) }
            if count < 0 { return }
            if count == 0 { continue }
            let data = Data(buffer.prefix(Int(count)))
            let family = buffer[0] >> 4 == 6 ? AF_INET6 : AF_INET
            if !packetFlow.writePackets([data], withProtocols: [NSNumber(value: family)]) {
                cancelTunnelWithError(failure(7)); return
            }
        }
    }
    private func watchPath(_ h: UInt64) {
        let m = NWPathMonitor(); monitor = m
        var previous: String?
        m.pathUpdateHandler = { [weak self] path in
            guard self?.current() == h else { return }
            let identity = "\(path.status)-" + path.availableInterfaces.map { $0.name }.sorted().joined(separator: ",")
            if let old = previous, old != identity { RLNetworkChanged(h) }
            previous = identity
        }
        m.start(queue: lifecycle)
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lifecycle.async { self.monitor?.cancel(); self.monitor = nil; self.abort(self.current()); self.finishStart(self.failure(8)); completionHandler() }
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let pointer: UnsafeMutablePointer<CChar>?
        if messageData == Data("status".utf8) { pointer = RLStatus(current()) }
        else if messageData == Data("events".utf8) { pointer = RLEvents(current()) }
        else { completionHandler?(nil); return }
        guard let p = pointer else { completionHandler?(nil); return }
        let data = Data(String(cString: p).utf8); RLFree(p); completionHandler?(data)
    }
}
