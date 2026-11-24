import Foundation
import Network
import Combine

// Ring buffer globale: tutto ciò che app/bridge/terminale producono finisce qui,
// così può essere letto via HTTP dal PC sulla stessa rete (niente screenshot).
final class DebugLog {
    static let shared = DebugLog()
    private let lock = NSLock()
    private var lines: [String] = []
    private let cap = 4000
    private let df: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    private init() {}

    func add(_ s: String) {
        lock.lock()
        let entry = "[\(df.string(from: Date()))] \(s)"
        lines.append(entry)
        if lines.count > cap { lines.removeFirst(lines.count - cap) }
        lock.unlock()
    }

    func snapshot(tail: Int?) -> String {
        lock.lock()
        let slice = tail.map { Array(lines.suffix($0)) } ?? lines
        lock.unlock()
        return slice.joined(separator: "\n") + "\n"
    }

    func clear() {
        lock.lock(); lines.removeAll(); lock.unlock()
    }

    var count: Int {
        lock.lock(); let n = lines.count; lock.unlock(); return n
    }
}

// Server di debug: HTTP minimale su TCP (porta configurabile, default 8787).
// GET /        ultime 600 righe (text/plain)
// GET /all     tutto il buffer
// GET /status  JSON con build, IP, porta, uptime, righe
// GET /clear   svuota il buffer
// Si attiva/disattiva dalle Impostazioni dell'app; la scelta è persistita.
final class DebugServer: ObservableObject {
    static let shared = DebugServer()

    @Published var enabled: Bool {
        didSet {
            UserDefaults.standard.set(enabled, forKey: "rhs.debug.enabled")
            enabled ? start() : stop()
        }
    }
    @Published var port: Int {
        didSet {
            UserDefaults.standard.set(port, forKey: "rhs.debug.port")
            if enabled { stop(); start() }
        }
    }
    @Published private(set) var running = false
    @Published var lastError = ""

    private var listener: NWListener?
    private let q = DispatchQueue(label: "rhs.debug.server")
    private let startedAt = Date()

    private init() {
        let d = UserDefaults.standard
        enabled = d.bool(forKey: "rhs.debug.enabled")
        let p = d.integer(forKey: "rhs.debug.port")
        port = p > 0 ? p : 8787
    }

    func startIfEnabled() {
        if enabled { start() }
    }

    func start() {
        guard listener == nil else { return }
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            lastError = "porta non valida"; return
        }
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            let l = try NWListener(using: params, on: nwPort)
            l.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
            l.stateUpdateHandler = { [weak self] st in
                DispatchQueue.main.async {
                    guard let self else { return }
                    switch st {
                    case .ready:
                        self.running = true
                        self.lastError = ""
                        DebugLog.shared.add("[debug] server HTTP ON :\(self.port)")
                    case .failed(let e):
                        self.running = false
                        self.lastError = "\(e)"
                        DebugLog.shared.add("[debug] server FAIL \(e)")
                    case .cancelled:
                        self.running = false
                    default:
                        break
                    }
                }
            }
            listener = l
            l.start(queue: q)
        } catch {
            lastError = "listen: \(error.localizedDescription)"
            running = false
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        if running { DebugLog.shared.add("[debug] server OFF") }
        running = false
    }

    var urlHint: String {
        let ip = DeviceNet.cachedIPv4()
        return ip.isEmpty ? "http://<IP-iPhone>:\(port)/" : "http://\(ip):\(port)/"
    }

    // MARK: - HTTP

    private func accept(_ conn: NWConnection) {
        conn.start(queue: q)
        read(conn, buffer: Data())
    }

    private func read(_ conn: NWConnection, buffer: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, complete, error in
            guard let self else { conn.cancel(); return }
            var buf = buffer
            if let data { buf.append(data) }
            let headerEnd = buf.range(of: Data("\r\n\r\n".utf8))
            if headerEnd != nil || complete || error != nil || buf.count > 16384 {
                self.respond(conn, request: buf)
            } else {
                self.read(conn, buffer: buf)
            }
        }
    }

    private func respond(_ conn: NWConnection, request: Data) {
        let head = String(decoding: request.prefix(2048), as: UTF8.self)
        let line = head.split(separator: "\r\n").first.map(String.init) ?? ""
        let path = line.split(separator: " ").dropFirst().first.map(String.init) ?? "/"

        var body: String
        var ctype = "text/plain; charset=utf-8"
        if path.hasPrefix("/status") {
            ctype = "application/json"
            body = statusJSON()
        } else if path.hasPrefix("/clear") {
            DebugLog.shared.clear()
            body = "cleared\n"
        } else if path.hasPrefix("/all") {
            body = DebugLog.shared.snapshot(tail: nil)
        } else {
            body = DebugLog.shared.snapshot(tail: 600)
        }

        let up = Int(Date().timeIntervalSince(startedAt))
        DebugLog.shared.add("[debug] GET \(path) → \(body.utf8.count) byte (up \(up)s)")

        let resp = "HTTP/1.1 200 OK\r\n"
            + "Content-Type: \(ctype)\r\n"
            + "Content-Length: \(body.utf8.count)\r\n"
            + "Connection: close\r\n"
            + "Access-Control-Allow-Origin: *\r\n"
            + "Cache-Control: no-store\r\n\r\n"
            + body
        conn.send(content: Data(resp.utf8), completion: .contentProcessed { _ in conn.cancel() })
    }

    private func statusJSON() -> String {
        let ip = DeviceNet.cachedIPv4()
        let up = Int(Date().timeIntervalSince(startedAt))
        return "{\"build\":\"\(ToolRegistry.buildTag)\",\"ip\":\"\(ip)\",\"port\":\(port),"
            + "\"running\":\(running),\"uptime\":\(up),\"lines\":\(DebugLog.shared.count)}\n"
    }
}
