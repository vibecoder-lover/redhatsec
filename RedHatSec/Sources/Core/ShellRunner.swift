import Foundation
import Security

// iOS 15+: l'exec diretto di binari setuid è negato dall'AMFI. Il root si ottiene
// con le persona spawn attributes (override uid/gid 0) — richiede l'entitlement
// com.apple.private.persona-mgmt. Ricetta da TSUtil.m di TrollStore.
@_silgen_name("posix_spawnattr_set_persona_np")
private func spawnattr_set_persona_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ id: uid_t, _ flags: UInt32) -> Int32

@_silgen_name("posix_spawnattr_set_persona_uid_np")
private func spawnattr_set_persona_uid(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ uid: uid_t) -> Int32

@_silgen_name("posix_spawnattr_set_persona_gid_np")
private func spawnattr_set_persona_gid(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ gid: gid_t) -> Int32

private let POSIX_SPAWN_PERSONA_FLAG_OVERRIDE: UInt32 = 1

// dump entitlements dal code signing: le SecCode* non sono visibili a Swift
// su iOS SDK, quindi si dichiarano raw. kSecCSRequirementInformation = 2,
// kSecCodeInfoEntitlementsDict = "entitlements".
@_silgen_name("SecCodeCopySelf")
private func secCodeCopySelf(_ flags: UInt32, _ code: UnsafeMutablePointer<UnsafeRawPointer?>) -> Int32

@_silgen_name("SecCodeCopySigningInformation")
private func secCodeCopySigningInformation(_ code: UnsafeRawPointer, _ flags: UInt32, _ info: UnsafeMutablePointer<CFDictionary?>) -> Int32

struct ShellResult {
    var exitCode: Int32
    var stdout: String
    var stderr: String
}

final class ShellRunner: ObservableObject {
    static let shared = ShellRunner()

    private let bootstrapRoots = ["/var/jb", "", "/usr/local", "/opt/jb"]

    private static let toolNames = ["nmap", "tcpdump", "aireplay-ng", "airodump-ng", "aircrack-ng",
                                    "hcxpcapngtool", "hcxdumptool", "hostapd", "mdk3", "reaver",
                                    "pixiewps", "yersinia", "ettercap", "killerbee", "zbdsniff",
                                    "zbjam", "dns-sd", "curl", "python3", "scapy"]

    @Published private(set) var availableTools: [String] = []
    private var resolveCache: [String: Bool] = [:]

    // cache: statusLabel/statusColor sono chiamati a ogni render per ogni riga PLAN
    func isAvailable(_ bin: String) -> Bool {
        if let v = resolveCache[bin] { return v }
        let v = resolve(bin) != nil
        resolveCache[bin] = v
        return v
    }

    // re-scan dopo ogni install: i pill "TOOL ✓/✗" e il contatore si aggiornano live
    func rescanTools() {
        resolveCache.removeAll()
        availableTools = Self.toolNames.filter { resolve($0) != nil }
    }

    private init() {
        rescanTools()
    }

    private var pathEnv: String {
        var parts: [String] = ["/var/jb/usr/local/bin", "/var/mobile/RedHatSec/bin"]
        for root in bootstrapRoots {
            let p = root.isEmpty ? "/usr/bin:/bin:/usr/sbin:/sbin" : "\(root)/usr/bin:\(root)/bin"
            parts.append(p)
        }
        return parts.joined(separator: ":")
    }

    func resolve(_ bin: String) -> String? {
        let fm = FileManager.default
        // shim netcat (nc -lvnp → -l -v -n -p) e altri override prima del bootstrap
        let jbLocal = "/var/jb/usr/local/bin/" + bin
        if fm.isExecutableFile(atPath: jbLocal) { return jbLocal }
        // app-installed binari prima
        let appBin = "/var/mobile/RedHatSec/bin"
        if fm.fileExists(atPath: appBin + "/" + bin) { return appBin + "/" + bin }
        for root in bootstrapRoots {
            let dirs = root.isEmpty ? ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                                    : ["\(root)/usr/bin", "\(root)/bin"]
            for d in dirs {
                let full = d + "/" + bin
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

    private func buildEnvp() -> [UnsafeMutablePointer<CChar>?] {
        var envp: [UnsafeMutablePointer<CChar>?] = []
        envp.append(strdup("PATH=\(pathEnv)"))
        envp.append(strdup("HOME=/var/mobile"))
        envp.append(strdup("TERM=xterm"))
        // senza LD_LIBRARY_PATH il fallback spawn non trova le dylib rootless → 127
        envp.append(strdup("LD_LIBRARY_PATH=/var/jb/usr/lib"))
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
        return runPath(bin, args: args, stdin: stdin, asRoot: asRoot, timeout: timeout)
    }

    // spawn per path assoluto — serve per l'helper nel bundle (non è nel PATH)
    func runPath(_ path: String, args: [String], stdin: Data?, asRoot: Bool = false, timeout: TimeInterval = 15) -> ShellResult {
        let bin = path
        let outPipe = Pipe()
        let errPipe = Pipe()
        let inPipe = stdin != nil ? Pipe() : nil
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr)
        var personaErr: Int32 = 0
        if asRoot {
            personaErr = spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAG_OVERRIDE)
            if personaErr == 0 { personaErr = spawnattr_set_persona_uid(&attr, 0) }
            if personaErr == 0 { personaErr = spawnattr_set_persona_gid(&attr, 0) }
        }
        var fileActions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fileActions)
        guard personaErr == 0 else {
            posix_spawnattr_destroy(&attr)
            posix_spawn_file_actions_destroy(&fileActions)
            return ShellResult(exitCode: -1, stdout: "",
                               stderr: "persona override fallita rc=\(personaErr) — entitlement com.apple.private.persona-mgmt assente")
        }
        // chiudi nel child i fd inutili e le copie dopo dup2: altrimenti il child
        // tiene aperta la pipe di scrittura e readDataToEndOfFile non ritorna mai
        posix_spawn_file_actions_addclose(&fileActions, outPipe.fileHandleForReading.fileDescriptor)
        posix_spawn_file_actions_addclose(&fileActions, errPipe.fileHandleForReading.fileDescriptor)
        if let inPipe {
            posix_spawn_file_actions_addclose(&fileActions, inPipe.fileHandleForWriting.fileDescriptor)
        }
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, errPipe.fileHandleForWriting.fileDescriptor, 2)
        posix_spawn_file_actions_addclose(&fileActions, outPipe.fileHandleForWriting.fileDescriptor)
        posix_spawn_file_actions_addclose(&fileActions, errPipe.fileHandleForWriting.fileDescriptor)
        if let inPipe {
            posix_spawn_file_actions_adddup2(&fileActions, inPipe.fileHandleForReading.fileDescriptor, 0)
            posix_spawn_file_actions_addclose(&fileActions, inPipe.fileHandleForReading.fileDescriptor)
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
            try? outPipe.fileHandleForReading.close()
            try? outPipe.fileHandleForWriting.close()
            try? errPipe.fileHandleForReading.close()
            try? errPipe.fileHandleForWriting.close()
            if let inPipe {
                try? inPipe.fileHandleForReading.close()
                try? inPipe.fileHandleForWriting.close()
            }
            let msg = String(cString: strerror(rc))
            return ShellResult(exitCode: Int32(rc), stdout: "",
                               stderr: "spawn failed rc=\(rc): \(msg) — bin: \(bin)")
        }
        try? outPipe.fileHandleForWriting.close()
        try? errPipe.fileHandleForWriting.close()
        if let inPipe {
            // stdin scritto in background: un payload > buffer pipe bloccherebbe
            // prima che partano i reader di stdout/stderr (deadlock fino al timeout)
            let data = stdin ?? Data()
            let w = inPipe.fileHandleForWriting
            DispatchQueue.global(qos: .userInitiated).async {
                if !data.isEmpty { try? w.write(contentsOf: data) }
                try? w.close()
            }
            try? inPipe.fileHandleForReading.close()
        }

        let grp = DispatchGroup()
        let lock = NSLock()
        var outData = Data()
        var errData = Data()
        grp.enter()
        DispatchQueue.global().async {
            let d = outPipe.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); outData = d; lock.unlock()
            grp.leave()
        }
        grp.enter()
        DispatchQueue.global().async {
            let d = errPipe.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); errData = d; lock.unlock()
            grp.leave()
        }

        var timedOut = false
        if grp.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            kill(pid, SIGKILL)
            _ = grp.wait(timeout: .now() + 3)
        }

        var status: Int32 = 0
        waitpid(pid, &status, 0)
        // raw waitpid status → exit code: WEXITSTATUS / 128+segnale
        let rawCode: Int32 = status & 0x7F != 0 ? Int32(128 + (status & 0x7F)) : Int32((status >> 8) & 0xFF)
        lock.lock()
        let snapOut = outData
        let snapErr = errData
        lock.unlock()
        let so = String(data: snapOut, encoding: .utf8)
            ?? String(data: snapOut, encoding: .isoLatin1) ?? ""
        let se = String(data: snapErr, encoding: .utf8)
            ?? String(data: snapErr, encoding: .isoLatin1) ?? ""
        let suffix = timedOut ? "\n[timeout \(timeout)s — killed]" : ""
        return ShellResult(exitCode: rawCode, stdout: so, stderr: se + suffix)
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

        // entitlements come li vede AMFI (dal code signing del binario in esecuzione)
        out.append("— ents on-disk (verità firma) —")
        out.append(Self.entsDump())
        var cSelf: UnsafeRawPointer? = nil
        out.append("SecCodeCopySelf rc=\(secCodeCopySelf(0, &cSelf))")

        out.append("— rootd 127.0.0.1:4444 —")
        let rd = RootdClient.exec("id -u", timeout: 6)
        if rd.exitCode == 0 {
            out.append("rootd OK → id -u = \(rd.stdout.trimmingCharacters(in: .whitespacesAndNewlines))")
        } else {
            out.append(rd.stderr)
        }

        // helper nel bundle: spawn in-container sempre permesso anche sandboxed
        let helper = Bundle.main.bundlePath + "/RHSHelper"
        if fm.fileExists(atPath: helper) {
            out.append("\(helper) +persona → \(spawnProbe(helper, root: true, args: ["id -u"]))")
        } else {
            out.append("RHSHelper — assente nel bundle")
        }
        return out
    }

    private static func u32(_ d: Data, _ o: UInt32) -> UInt32 {
        let off = Int(o)
        guard off >= 0, off + 4 <= d.count else { return 0 }
        return d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: off, as: UInt32.self) }
    }

    // parse della firma embedded: LC_CODE_SIGNATURE → superblob → slot entitlements
    static func entsDump() -> String {
        guard let path = Bundle.main.executablePath,
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return "impossibile leggere il binario"
        }
        guard data.count >= 32, u32(data, 0) == 0xFEEDFACF else {
            return "binario non thin arm64"
        }
        let ncmds = u32(data, 16)
        var off: UInt32 = 32
        var sigOff: UInt32 = 0
        for _ in 0..<ncmds {
            guard Int(off) + 8 <= data.count else { break }
            let cmd = u32(data, off)
            let cmdsize = u32(data, off + 4)
            if cmd == 0x1D { sigOff = u32(data, off + 8) } // LC_CODE_SIGNATURE: dataoff a +8
            if cmdsize == 0 { break }
            off += cmdsize
        }
        guard sigOff > 0 else { return "nessuna LC_CODE_SIGNATURE" }
        // i blob CodeSigning sono big-endian (Mach-O LE, blob BE)
        func u32be(_ d: Data, _ o: UInt32) -> UInt32 {
            let v = u32(d, o)
            return (v << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24)
        }
        let sbMagic = u32be(data, sigOff)
        guard sbMagic == 0xFADE0B01 else {
            return "superblob magic err: 0x\(String(u32be(data, sigOff), radix: 16))"
        }
        let count = u32be(data, sigOff + 8)
        var entsXML = ""
        var idx = sigOff + 12
        for _ in 0..<count {
            guard Int(idx) + 8 <= data.count else { break }
            let type = u32be(data, idx)
            let o = u32be(data, idx + 4)
            if type == 0x10007 { // CSSLOT_ENTITLEMENTS
                let blobOff = sigOff + o
                guard u32be(data, blobOff) == 0xFADE7171 else { return "ent blob magic err" }
                let bLen = Int(u32be(data, blobOff + 4))
                if bLen > 8, Int(blobOff) + bLen <= data.count {
                    entsXML = String(data: data[(Int(blobOff) + 8)..<(Int(blobOff) + bLen)], encoding: .utf8) ?? ""
                }
            }
            idx += 8
        }
        guard !entsXML.isEmpty else { return "slot entitlements ASSENTE dalla firma" }
        return entsXML.replacingOccurrences(of: "\n", with: " ").prefix(600).description
    }

    static func ownEntitlementKeys() -> [String] {
        var code: UnsafeRawPointer? = nil
        guard secCodeCopySelf(0, &code) == 0, let code else {
            return ["SecCodeCopySelf fallita"]
        }
        var info: CFDictionary? = nil
        guard secCodeCopySigningInformation(code, 2, &info) == 0, let info else {
            return ["SecCodeCopySigningInformation fallita"]
        }
        guard let ent = (info as NSDictionary)["entitlements"] as? [String: Any] else {
            return ["nessun entitlement nel codice"]
        }
        return ent.keys.sorted()
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
        posix_spawn_file_actions_addclose(&fileActions, outPipe.fileHandleForReading.fileDescriptor)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 2)
        posix_spawn_file_actions_addclose(&fileActions, outPipe.fileHandleForWriting.fileDescriptor)

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
        posix_spawn_file_actions_addclose(&fileActions, outPipe.fileHandleForReading.fileDescriptor)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 1)
        posix_spawn_file_actions_adddup2(&fileActions, outPipe.fileHandleForWriting.fileDescriptor, 2)
        posix_spawn_file_actions_addclose(&fileActions, outPipe.fileHandleForWriting.fileDescriptor)

        var argv = buildArgv(bin: bin, args: args)
        var envp = buildEnvp()
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, bin, &fileActions, &attr, &argv, &envp)

        posix_spawnattr_destroy(&attr)
        posix_spawn_file_actions_destroy(&fileActions)
        for p in argv { if let p { free(p) } }
        for p in envp { if let p { free(p) } }

        guard rc == 0 else {
            try? outPipe.fileHandleForReading.close()
            try? outPipe.fileHandleForWriting.close()
            line("spawn failed rc=\(rc)")
            onExit(Int32(rc))
            return
        }
        try? outPipe.fileHandleForWriting.close()

        DispatchQueue.global(qos: .utility).async {
            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            let s = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1) ?? ""
            let rows = s.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            let code: Int32 = status & 0x7F != 0 ? Int32(128 + (status & 0x7F)) : Int32((status >> 8) & 0xFF)
            DispatchQueue.main.async {
                for l in rows { line(l) }
                onExit(code)
            }
        }
    }
}
