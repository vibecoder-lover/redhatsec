import Foundation

// iOS 15+: l'exec diretto di binari setuid è negato dall'AMFI. Il root si ottiene
// con le persona spawn attributes (override uid/gid 0) — richiede l'entitlement
// com.apple.private.persona-mgmt. Ricetta da TSUtil.m di TrollStore.
@_silgen_name("posix_spawnattr_set_persona_np")
private func spawnattr_set_persona_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t>, _ id: uid_t, _ flags: UInt32) -> Int32

@_silgen_name("posix_spawnattr_set_persona_uid_np")
private func spawnattr_set_persona_uid(_ attr: UnsafeMutablePointer<posix_spawnattr_t>, _ uid: uid_t) -> Int32

@_silgen_name("posix_spawnattr_set_persona_gid_np")
private func spawnattr_set_persona_gid(_ attr: UnsafeMutablePointer<posix_spawnattr_t>, _ gid: gid_t) -> Int32

private let POSIX_SPAWN_PERSONA_FLAG_OVERRIDE: UInt32 = 1

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
        return runWithStdin(cmd, args: args, stdin: nil, timeout: timeout)
    }

    // run con stdin: serve per sudo -S (password su stdin)
    func runWithStdin(_ cmd: String, args: [String], stdin: Data?, asRoot: Bool = false, timeout: TimeInterval = 15) -> ShellResult {
        guard let bin = resolve(cmd) else {
            return ShellResult(exitCode: 127, stdout: "", stderr: "tool not found: \(cmd)")
        }
        let outPipe = Pipe()
        let errPipe = Pipe()
        let inPipe = stdin != nil ? Pipe() : nil
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr)
        if asRoot {
            spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAG_OVERRIDE)
            spawnattr_set_persona_uid(&attr, 0)
            spawnattr_set_persona_gid(&attr, 0)
        }
        var fileActions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, errPipe.fileHandleForWriting.fileDescriptor, 2)
        if let inPipe {
            posix_spawn_file_actions_adddup2(&fileActions, inPipe.fileHandleForReading.fileDescriptor, 0)
        }

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
        if let inPipe {
            // scrivo stdin e chiudo: il child vede EOF subito dopo
            if let data = stdin {
                try? inPipe.fileHandleForWriting.write(contentsOf: data)
            }
            try? inPipe.fileHandleForWriting.close()
            try? inPipe.fileHandleForReading.close()
        }

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

    // MARK: diagnostica spawn — spawntest

    func probeSpawn() -> [String] {
        var out: [String] = []
        let fm = FileManager.default
        let targets: [(String, Bool, [String])] = [
            ("/bin/ls", false, ["-1", "/"]),
            ("/usr/bin/id", false, []),
            ("/var/jb/usr/bin/sh", false, ["-c", "echo jb-sh-ok"]),
            ("/var/jb/usr/bin/sh", true, ["-c", "id -u"]),
            ("/var/jb/usr/bin/whoami", true, []),
        ]
        for (path, root, args) in targets {
            guard fm.fileExists(atPath: path) else {
                out.append("\(path) — assente")
                continue
            }
            out.append("\(path)\(root ? " +persona" : "") → \(spawnProbe(path, root: root, args: args))")
        }
        return out
    }

    private func spawnProbe(_ path: String, root: Bool, args: [String]) -> String {
        let outPipe = Pipe()
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr)
        if root {
            spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAG_OVERRIDE)
            spawnattr_set_persona_uid(&attr, 0)
            spawnattr_set_persona_gid(&attr, 0)
        }
        var fileActions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 2)

        var argv = buildArgv(bin: path, args: args)
        var envp = buildEnvp()
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, path, &fileActions, &attr, &argv, &envp)
        posix_spawnattr_destroy(&attr)
        posix_spawn_file_actions_destroy(&fileActions)
        for p in argv { if let p { free(p) } }
        for p in envp { if let p { free(p) } }
        guard rc == 0 else { return "spawn rc=\(rc) \(String(cString: strerror(rc)))" }
        try? outPipe.fileHandleForWriting.close()
        var data = Data()
        DispatchQueue.global().sync { data = outPipe.fileHandleForReading.readDataToEndOfFile() }
        var st: Int32 = 0
        waitpid(pid, &st, 0)
        let s = String(data: data.prefix(160), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return "exit=\(st >> 8) out: \(s.isEmpty ? "(vuoto)" : s)"
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
