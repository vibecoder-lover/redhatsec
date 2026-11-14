import Foundation
import Network
import Combine

// Root via rootd: launchd inetd su 127.0.0.1:4444.
// launchd (root) spawna /var/jb/usr/bin/sh per ogni connessione, con il socket
// come stdin/stdout. L'app manda "RHSROOT:<cmd>\n" e legge fino a EOF.
// Nessuno spawn dall'app (l'AMFI lo nega: SecCodeCopySelf rc=-67065 = unsigned).
private final class RootdState {
    let lock = NSLock()
    private var buf = Data()
    private var errMsg = ""
    private var finished = false
    let sem = DispatchSemaphore(value: 0)

    func append(_ d: Data) { lock.lock(); buf += d; lock.unlock() }
    var out: String {
        lock.lock(); defer { lock.unlock() }
        return String(data: buf, encoding: .utf8) ?? String(decoding: buf, as: UTF8.self)
    }
    var error: String { lock.lock(); defer { lock.unlock() }; return errMsg }

    func fail(_ m: String) {
        lock.lock()
        let first = !finished
        if first { finished = true; errMsg = m }
        lock.unlock()
        if first { sem.signal() }
    }
    func finish() {
        lock.lock()
        let first = !finished
        if first { finished = true }
        lock.unlock()
        if first { sem.signal() }
    }
}

enum RootdClient {
    static func exec(_ cmd: String, timeout: TimeInterval) -> ShellResult {
        let st = RootdState()
        let conn = NWConnection(host: "127.0.0.1", port: 4444, using: .tcp)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: Data("RHSROOT:\(cmd)\n".utf8), completion: .contentProcessed { _ in
                    recvAll(conn, st)
                })
            case .failed(let e):
                st.fail("rootd: connessione fallita (\(e)) — installa rhs-sudoers.deb v1.1")
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "rhs.rootd"))
        if st.sem.wait(timeout: .now() + timeout) == .timedOut {
            conn.cancel()
            _ = st.sem.wait(timeout: .now() + 2)
            return ShellResult(exitCode: -1, stdout: st.out, stderr: "[rootd timeout \(Int(timeout))s]")
        }
        conn.cancel()
        return ShellResult(exitCode: st.error.isEmpty ? 0 : -1, stdout: st.out, stderr: st.error)
    }

    private static func recvAll(_ conn: NWConnection, _ st: RootdState) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 16384) { data, _, isEOF, err in
            if let data, !data.isEmpty { st.append(data) }
            if isEOF {
                st.finish()
                return
            }
            if let err {
                st.fail("rootd: recv err (\(err)) — rootd non attivo? reinstalla rhs-sudoers.deb v1.1")
                return
            }
            recvAll(conn, st)
        }
    }
}

final class RootShell: ObservableObject {
    static let shared = RootShell()

    @Published var password: String = ""
    @Published var lastRootOK = false

    var available: Bool {
        ShellRunner.shared.resolve("sh") != nil
    }

    func runSync(_ cmd: String, timeout: TimeInterval = 180) -> ShellResult {
        // 1) rootd via TCP: launchd (root) spawna sh per noi
        let rd = RootdClient.exec(cmd, timeout: timeout)
        if rd.exitCode == 0 {
            lastRootOK = true
            return rd
        }
        let wrapped = "export DEBIAN_FRONTEND=noninteractive; \(cmd)"
        // 2) fallback: persona spawn diretto di sh (uid 0 override)
        let a = ShellRunner.shared.runWithStdin("sh", args: ["-c", wrapped], stdin: nil, asRoot: true, timeout: timeout)
        if !a.stderr.contains("spawn failed") {
            lastRootOK = a.exitCode == 0
            return a
        }
        // 3) fallback: helper nel bundle
        let helper = Bundle.main.bundlePath + "/RHSHelper"
        if FileManager.default.fileExists(atPath: helper) {
            let b = ShellRunner.shared.runPath(helper, args: [wrapped], stdin: nil, asRoot: true, timeout: timeout)
            lastRootOK = b.exitCode == 0
            return b
        }
        lastRootOK = false
        return ShellResult(exitCode: -1, stdout: rd.stdout, stderr: rd.stderr + "\n[RHSHelper] assente nel bundle")
    }

    func run(_ cmd: String, timeout: TimeInterval = 180) async -> ShellResult {
        await Task.detached { [self] in
            self.runSync(cmd, timeout: timeout)
        }.value
    }
}
