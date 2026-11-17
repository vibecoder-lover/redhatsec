import Foundation
import Network

// IP locale del device (iPhone): serve come default nei campi "attacker host"
// e per costruire subnet/ping sweep senza dipendere dal bridge ESP.
enum DeviceNet {
    static func localIPv4() -> String {
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let first = addrs else { return "" }
        defer { freeifaddrs(first) }

        var fallback = ""
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cur {
            defer { cur = p.pointee.ifa_next }
            let f = p.pointee
            guard let sa = f.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let rc = getnameinfo(sa, socklen_t(sa.pointee.sa_len),
                                 &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST)
            guard rc == 0 else { continue }
            let ip = String(cString: buf)
            let name = String(cString: f.ifa_name)
            if name == "en0" { return ip }
            if ip.hasPrefix("169.254.") || ip.hasPrefix("127.") { continue }
            if fallback.isEmpty { fallback = ip }
        }
        return fallback
    }

    // "192.168.1.37" -> "192.168.1.0/24"
    static func localSubnetCIDR() -> String {
        let ip = localIPv4()
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return "" }
        return "\(parts[0]).\(parts[1]).\(parts[2]).0/24"
    }

    static func localPrefix() -> String {
        let ip = localIPv4()
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return "" }
        return "\(parts[0]).\(parts[1]).\(parts[2])."
    }
}

// MARK: - Scansione LAN nativa (TCP connect via NWConnection)

extension DeviceNet {
    static func tcpOpen(_ host: String, _ port: UInt16, timeout: TimeInterval = 0.35) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            guard let p = NWEndpoint.Port(rawValue: port) else {
                cont.resume(returning: false)
                return
            }
            let lock = NSLock()
            var done = false
            let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
            func finish(_ ok: Bool) {
                lock.lock()
                if done { lock.unlock(); return }
                done = true
                lock.unlock()
                conn.cancel()
                cont.resume(returning: ok)
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                default: break
                }
            }
            let q = DispatchQueue(label: "rhs.tcp.probe")
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    // /24 locale: TCP connect su porte comuni. Restituisce ip -> porte aperte.
    static func lanSweep(ports: [UInt16] = [80, 443, 22, 62078],
                         concurrency: Int = 32,
                         timeout: TimeInterval = 0.35) async -> [(ip: String, open: [UInt16])] {
        let prefix = localPrefix()
        guard !prefix.isEmpty else { return [] }
        let hosts = (1...254).map { "\(prefix)\($0)" }
        var found: [String: [UInt16]] = [:]
        var idx = 0
        while idx < hosts.count {
            let end = min(idx + concurrency, hosts.count)
            let batch = Array(hosts[idx..<end])
            await withTaskGroup(of: (String, UInt16, Bool).self) { group in
                for h in batch {
                    for p in ports {
                        group.addTask { (h, p, await tcpOpen(h, p, timeout: timeout)) }
                    }
                }
                for await (h, p, ok) in group where ok {
                    found[h, default: []].append(p)
                }
            }
            idx = end
        }
        return found
            .map { (ip: $0.key, open: $0.value.sorted()) }
            .sorted { lastOctet($0.ip) < lastOctet($1.ip) }
    }

    private static func lastOctet(_ ip: String) -> Int {
        Int(ip.components(separatedBy: ".").last ?? "0") ?? 0
    }

    // banner HTTP (Server header) + <title> per dare un nome leggibile ai target LAN
    static func httpTitle(_ host: String, port: UInt16 = 80) async -> String? {
        guard let url = URL(string: "http://\(host):\(port)/") else { return nil }
        var req = URLRequest(url: url)
        req.timeoutInterval = 2
        req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X)", forHTTPHeaderField: "User-Agent")
        guard let (data, resp) = try? await URLSession.shared.data(for: req) else { return nil }

        var server = ""
        if let http = resp as? HTTPURLResponse,
           let s = http.value(forHTTPHeaderField: "Server") {
            server = s.split(separator: " ").first.map { String($0) } ?? s
            if server.count > 24 { server = String(server.prefix(24)) }
        }

        var title = ""
        if let body = String(data: data.prefix(8192), encoding: .utf8),
           let open = body.range(of: "<title", options: .caseInsensitive),
           let close = body.range(of: "</title>", options: .caseInsensitive),
           let gt = body[open.upperBound...].firstIndex(of: ">"),
           gt < close.lowerBound {
            let inner = body[body.index(after: gt)..<close.lowerBound]
            title = inner.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if title.count > 40 { title = String(title.prefix(40)) }
        }

        let parts = [server, title].filter { !$0.isEmpty }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}
