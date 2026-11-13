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
        var parts: [String] = ["/var/mobile/RedHatSec/bin"]
        for root in bootstrapRoots {
            let p = root.isEmpty ? "/usr/bin:/bin:/usr/sbin:/sbin" : "\(root)/usr/bin:\(root)/bin"
            parts.append(p)
        }
        return parts.joined(separator: ":")
    }

    func resolve(_ bin: String) -> String? {
        let fm = FileManager.default
        // app-installed binari prima
        let appBin = "/var/mobile/RedHatSec/bin"
        if fm.fileExists(atPath: appBin + "/" + bin) { return appBin + "/" + bin }
        for root in bootstrapRoots {
            let dirs = root.isEmpty ? ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                                    : ["\(root)/usr/bin", "\(root)/bin"]
            for d in dirs {
                let full = d + "/" + bin
                if fm.isExecutableFile(atPath: full) || fm.fileExists(atPath: full) { return full }
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

    private func buildEnvp() -> [UnsafeMutablePointer<CChar>?] {
        var envp: [UnsafeMutablePointer<CChar>?] = []
        envp.append(strdup("PATH=\(pathEnv)"))
        envp.append(strdup("HOME=/var/mobile"))
        envp.append(strdup("TERM=xterm"))
        envp.append(nil)
        return envp
    }

    private func buildArgv(bin: String, args: [String]) -> [UnsafeMutablePointer<CChar>?] {
        var argv: [UnsafeMutablePointer<CChar>?] = []
        argv.append(strdup(bin))
        for a in args { argv.append(strdup(a)) }
        argv.append(nil)
        return argv
    }

    func run(_ cmd: String, args: [String], timeout: TimeInterval = 15) -> ShellResult {
        guard let bin = resolve(cmd) else {
            return ShellResult(exitCode: 127, stdout: "", stderr: "tool not found: \(cmd)")
        }
        let outPipe = Pipe()
        let errPipe = Pipe()
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr)
        var fileActions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, errPipe.fileHandleForWriting.fileDescriptor, 2)

        var argv = buildArgv(bin: bin, args: args)
        var envp = buildEnvp()
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, bin, &fileActions, &attr, &argv, &envp)

        posix_spawnattr_destroy(&attr)
        posix_spawn_file_actions_destroy(&fileActions)
        for p in argv { if let p { free(p) } }
        for p in envp { if let p { free(p) } }

        guard rc == 0 else {
            let msg = String(cString: strerror(rc))
            return ShellResult(exitCode: Int32(rc), stdout: "",
                               stderr: "spawn failed rc=\(rc): \(msg) — bin: \(bin)")
        }
        try? outPipe.fileHandleForWriting.close()
        try? errPipe.fileHandleForWriting.close()

        let grp = DispatchGroup()
        var outData = Data()
        var errData = Data()
        grp.enter()
        DispatchQueue.global().async { outData = outPipe.fileHandleForReading.readDataToEndOfFile(); grp.leave() }
        grp.enter()
        DispatchQueue.global().async { errData = errPipe.fileHandleForReading.readDataToEndOfFile(); grp.leave() }

        var timedOut = false
        if grp.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            kill(pid, SIGKILL)
            _ = grp.wait(timeout: .now() + 3)
        }

        var status: Int32 = 0
        waitpid(pid, &status, 0)
        let so = String(data: outData, encoding: .utf8)
            ?? String(data: outData, encoding: .isoLatin1) ?? ""
        let se = String(data: errData, encoding: .utf8)
            ?? String(data: errData, encoding: .isoLatin1) ?? ""
        let suffix = timedOut ? "\n[timeout \(timeout)s — killed]" : ""
        return ShellResult(exitCode: status, stdout: so, stderr: se + suffix)
    }

    func stream(_ cmd: String, args: [String], line: @escaping (String) -> Void,
                onExit: @escaping (Int32) -> Void = { _ in }) {
        guard let bin = resolve(cmd) else {
            line("tool not found: \(cmd)")
            onExit(127)
            return
        }
        let outPipe = Pipe()
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr)
        var fileActions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 2)

        var argv = buildArgv(bin: bin, args: args)
        var envp = buildEnvp()
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, bin, &fileActions, &attr, &argv, &envp)

        posix_spawnattr_destroy(&attr)
        posix_spawn_file_actions_destroy(&fileActions)
        for p in argv { if let p { free(p) } }
        for p in envp { if let p { free(p) } }

        guard rc == 0 else { line("spawn failed rc=\(rc)"); onExit(Int32(rc)); return }
        try? outPipe.fileHandleForWriting.close()

        DispatchQueue.global(qos: .utility).async {
            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            let s = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1) ?? ""
            for l in s.split(separator: "\n", omittingEmptySubsequences: false) {
                line(String(l))
            }
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            onExit(status)
        }
    }
}
