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
        let outPipe = Pipe()
        let errPipe = Pipe()
        var attr = posix_spawnattr_t()
        posix_spawnattr_init(&attr)
        var fileActions = posix_spawn_file_actions_t()
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, errPipe.fileHandleForWriting.fileDescriptor, 2)

        var argv: [UnsafeMutablePointer<CChar>?] = []
        argv.append(strdup(bin))
        for a in args { argv.append(strdup(a)) }
        argv.append(nil)

        var envp: [UnsafeMutablePointer<CChar>?] = []
        envp.append(strdup("PATH=\(pathEnv)"))
        envp.append(strdup("HOME=/var/mobile"))
        envp.append(strdup("TERM=xterm"))
        envp.append(nil)

        var pid: pid_t = 0
        let rc = posix_spawn(&pid, bin, &fileActions, &attr, &argv, &envp)

        defer {
            for p in argv { if let p { free(p) } }
            for p in envp { if let p { free(p) } }
            posix_spawnattr_destroy(&attr)
            posix_spawn_file_actions_destroy(&fileActions)
        }
        guard rc == 0 else {
            return ShellResult(exitCode: Int32(rc), stdout: "", stderr: "spawn failed rc=\(rc)")
        }

        try? outPipe.fileHandleForWriting.close()
        try? errPipe.fileHandleForWriting.close()

        let group = DispatchGroup()
        var outData = Data()
        var errData = Data()
        group.enter()
        DispatchQueue.global().async { outData = outPipe.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        group.enter()
        DispatchQueue.global().async { errData = errPipe.fileHandleForReading.readDataToEndOfFile(); group.leave() }

        let timedOut = group.wait(timeout: .now() + timeout) == .timedOut
        var code: Int32 = 0
        if timedOut {
            kill(pid, SIGKILL)
            code = -1
        } else {
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            code = status
        }
        let so = String(data: outData, encoding: .utf8) ?? ""
        let se = String(data: errData, encoding: .utf8) ?? ""
        return ShellResult(exitCode: code, stdout: so, stderr: se)
    }

    func stream(_ cmd: String, args: [String], line: @escaping (String) -> Void,
                onExit: @escaping (Int32) -> Void = { _ in }) {
        guard let bin = resolve(cmd) else {
            line("tool not found: \(cmd)")
            onExit(127)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            let outPipe = Pipe()
            var attr = posix_spawnattr_t()
            posix_spawnattr_init(&attr)
            var fileActions = posix_spawn_file_actions_t()
            posix_spawn_file_actions_init(&fileActions)
            posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
            posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 2)
            var argv: [UnsafeMutablePointer<CChar>?] = []
            argv.append(strdup(bin))
            for a in args { argv.append(strdup(a)) }
            argv.append(nil)
            var envp: [UnsafeMutablePointer<CChar>?] = []
            envp.append(strdup("PATH=\(self.pathEnv)"))
            envp.append(nil)
            var pid: pid_t = 0
            let rc = posix_spawn(&pid, bin, &fileActions, &attr, &argv, &envp)
            defer {
                for p in argv { if let p { free(p) } }
                for p in envp { if let p { free(p) } }
                posix_spawnattr_destroy(&attr)
                posix_spawn_file_actions_destroy(&fileActions)
            }
            if rc != 0 { line("spawn failed rc=\(rc)"); onExit(Int32(rc)); return }
            try? outPipe.fileHandleForWriting.close()
            let fh = outPipe.fileHandleForReading
            fh.waitForDataInBackgroundAndNotify()
            while true {
                let d = fh.availableData
                if d.isEmpty {
                    var status: Int32 = 0
                    waitpid(pid, &status, 0)
                    onExit(status)
                    return
                }
                autoreleasepool {
                    if let s = String(data: d, encoding: .utf8) {
                        for l in s.split(separator: "\n", omittingEmptySubsequences: false) {
                            line(String(l))
                        }
                    }
                }
            }
        }
    }
}
