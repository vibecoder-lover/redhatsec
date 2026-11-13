import Foundation

struct ShellResult {
    var exitCode: Int32
    var stdout: String
    var stderr: String
}

final class ShellRunner {
    static let shared = ShellRunner()

    private let bootstrapRoots = ["/var/jb", "", "/usr/local", "/opt/jb"]

    private(set) lazy var availableTools: [String] = {
        let names = ["nmap", "tcpdump", "aireplay-ng", "airodump-ng", "aircrack-ng",
                     "hcxpcapngtool", "hcxdumptool", "hostapd", "mdk3", "reaver",
                     "pixiewps", "yersinia", "ettercap", "killerbee", "zbdsniff",
                     "zbjam", "dns-sd", "curl", "python3", "scapy"]
        return names.filter { resolve($0) != nil }
    }()

    private var pathEnv: String {
        var parts: [String] = []
        for root in bootstrapRoots {
            let p = root.isEmpty ? "/usr/bin:/bin:/usr/sbin:/sbin" : "\(root)/usr/bin:\(root)/bin"
            parts.append(p)
        }
        return parts.joined(separator: ":")
    }

    func resolve(_ bin: String) -> String? {
        let fm = FileManager.default
        for root in bootstrapRoots {
            let prefix = root.isEmpty ? "" : root
            let dirs = root.isEmpty ? ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                                    : ["\(root)/usr/bin", "\(root)/bin"]
            for d in dirs {
                let full = prefix + d + "/" + bin
                if fm.isExecutableFile(atPath: full) { return full }
            }
        }
        return nil
    }

    var isJailbroken: Bool {
        FileManager.default.fileExists(atPath: "/var/jb/usr/bin") ||
        FileManager.default.fileExists(atPath: "/usr/bin/sshd") ||
        FileManager.default.fileExists(atPath: "/.bootstrapped") ||
        FileManager.default.fileExists(atPath: "/Applications/Cydia.app") ||
        FileManager.default.fileExists(atPath: "/var/jb/.installed_trollstore_helper")
    }

    func run(_ cmd: String, args: [String], timeout: TimeInterval = 15) -> ShellResult {
        guard let bin = resolve(cmd) else {
            return ShellResult(exitCode: 127, stdout: "", stderr: "tool not found: \(cmd)")
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = pathEnv
        env["HOME"] = "/var/mobile"
        env["TERM"] = "xterm"
        p.environment = env
        let outPipe = Pipe()
        let errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        do { try p.run() } catch {
            return ShellResult(exitCode: 126, stdout: "", stderr: "spawn failed: \(error)")
        }

        var timedOut = false
        let watchdog = DispatchWorkItem {
            if p.isRunning { timedOut = true; p.terminate() }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: watchdog)

        let grp = DispatchGroup()
        var outData = Data()
        var errData = Data()
        grp.enter()
        DispatchQueue.global().async { outData = outPipe.fileHandleForReading.readDataToEndOfFile(); grp.leave() }
        grp.enter()
        DispatchQueue.global().async { errData = errPipe.fileHandleForReading.readDataToEndOfFile(); grp.leave() }
        _ = grp.wait(timeout: .now() + timeout + 2)
        if p.isRunning {
            p.terminate()
            p.waitUntilExit()
        }
        watchdog.cancel()

        let so = String(data: outData, encoding: .utf8)
            ?? String(data: outData, encoding: .isoLatin1) ?? ""
        let se = String(data: errData, encoding: .utf8)
            ?? String(data: errData, encoding: .isoLatin1) ?? ""
        let suffix = timedOut ? "\n[timeout \(timeout)s — terminated]" : ""
        return ShellResult(exitCode: p.terminationStatus,
                           stdout: so, stderr: se + suffix)
    }

    func stream(_ cmd: String, args: [String], line: @escaping (String) -> Void,
                onExit: @escaping (Int32) -> Void = { _ in }) {
        guard let bin = resolve(cmd) else {
            line("tool not found: \(cmd)")
            onExit(127)
            return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = pathEnv
        env["HOME"] = "/var/mobile"
        env["TERM"] = "xterm"
        p.environment = env
        let outPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = outPipe

        var buffer = ""
        outPipe.fileHandleForReading.readabilityHandler = { fh in
            let d = fh.availableData
            if d.isEmpty {
                fh.readabilityHandler = nil
                return
            }
            if let s = String(data: d, encoding: .utf8) ?? String(data: d, encoding: .isoLatin1) {
                buffer += s
                let lines = buffer.components(separatedBy: "\n")
                guard lines.count > 1 else { return }
                buffer = lines.last ?? ""
                for l in lines.dropLast() { line(l) }
            }
        }
        p.terminationHandler = { proc in
            if !buffer.isEmpty { line(buffer) }
            onExit(proc.terminationStatus)
        }
        do { try p.run() } catch {
            line("spawn failed: \(error)")
            onExit(126)
        }
    }
}
