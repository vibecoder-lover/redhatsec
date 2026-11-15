import Foundation
import UIKit

struct ToolSpec {
    let name: String
    let pkg: String
    let bins: [String]
    var debURL: String? = nil
}

@_silgen_name("proc_pidpath")
func proc_pidpath_c(_ pid: pid_t, _ buf: UnsafeMutablePointer<CChar>, _ size: UInt32) -> Int32

enum BuiltinExec {
    static let names: Set<String> = ["ls", "cat", "echo", "whoami", "id", "uname",
                                     "env", "df", "ps", "ifconfig", "pwd", "help", "clear", "spawntest", "repo"]

    static func exec(_ parts: [String]) -> [String]? {
        guard let head = parts.first, names.contains(head), head != "clear" else { return nil }
        let args = Array(parts.dropFirst())
        switch head {
        case "help": return helpLines
        case "spawntest": return ShellRunner.shared.probeSpawn()
        case "pwd": return [FileManager.default.currentDirectoryPath]
        case "echo": return [args.joined(separator: " ")]
        case "whoami": return [userLine]
        case "id": return [idLine]
        case "uname": return [unameLine(args.contains("-a"))]
        case "env": return ProcessInfo.processInfo.environment.map { "\($0)=\($1)" }.sorted()
        case "df": return dfLines
        case "ifconfig": return ifconfigLines
        case "ls": return lsLines(args)
        case "cat": return catLines(args)
        case "ps": return psLines
        case "repo": return ToolRegistry.repoCmd(args)
        default: return nil
        }
    }

    static let helpLines: [String] = [
        "builtin nativi (no fork, sempre funzionanti):",
        "  ls [dir] · cat <file> · pwd · echo · whoami · id · uname [-a]",
        "  env · df · ifconfig · ps · clear · help",
        "  install <tool>   → auto-install da repo (fallback Sileo)",
        "  repo list/add/del → gestisci sorgenti apt RHS (\(ToolRegistry.sourcesPath))",
        "  spawntest        → diagnostica posix_spawn (persona root)",
        "  sudo <cmd>       → exec root via persona spawn",
        "  altri comandi    → exec via posix_spawn (richiede entitlements no-container)",
    ]

    static var userLine: String {
        let uid = getuid()
        if let pw = getpwuid(uid), let name = pw.pointee.pw_name {
            return String(cString: name)
        }
        return "uid=\(uid)"
    }

    static var idLine: String {
        let ruid = getuid()
        let euid = geteuid()
        var gids = [gid_t](repeating: 0, count: 16)
        let n = getgroups(16, &gids)
        let glist = (0..<max(0, Int(n))).map { String(gids[$0]) }.joined(separator: ",")
        return "uid=\(ruid) euid=\(euid) gid=\(getgid()) groups=\(glist)"
    }

    static func unameLine(_ full: Bool) -> String {
        var u = utsname()
        uname(&u)
        func cstr(_ ptr: UnsafeRawBufferPointer) -> String {
            String(cString: ptr.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        let sys = withUnsafeBytes(of: &u.sysname) { cstr($0) }
        let node = withUnsafeBytes(of: &u.nodename) { cstr($0) }
        let rel = withUnsafeBytes(of: &u.release) { cstr($0) }
        let ver = withUnsafeBytes(of: &u.version) { cstr($0) }
        let mach = withUnsafeBytes(of: &u.machine) { cstr($0) }
        if full {
            return "\(sys) \(node) \(rel) \(ver) \(mach)"
        }
        return sys
    }

    static var dfLines: [String] {
        var out = ["Filesystem       Size(M)  Free(M)  Cap  Mounted"]
        for url in ["/", "/private/var", "/var/jb"] {
            var s = statfs()
            if statfs(url, &s) == 0 {
                let block = UInt64(s.f_bsize)
                let total = UInt64(s.f_blocks) * block / 1024 / 1024
                let free = UInt64(s.f_bavail) * block / 1024 / 1024
                let cap = Double(total - free) * 100.0 / Double(max(1, total))
                let name = withUnsafeBytes(of: &s.f_mntonname) { p in
                    String(cString: p.baseAddress!.assumingMemoryBound(to: CChar.self))
                }
                    .padding(toLength: 16, withPad: " ", startingAt: 0)
                out.append("\(name) \(total)M \(free)M \(Int(cap))%  \(url)")
            }
        }
        return out
    }

    static var ifconfigLines: [String] {
        var addrs: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&addrs) == 0, let first = addrs else { return ["ifconfig: fallito"] }
        defer { freeifaddrs(first) }
        var out: [String] = []
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let p = ptr {
            let ifa = p.pointee
            let name = String(cString: ifa.ifa_name)
            if let sa = ifa.ifa_addr {
                var host = [CChar](repeating: 0, count: 128)
                if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(128), nil, 0, NI_NUMERICHOST) == 0 {
                    out.append("\(name): \(String(cString: host))")
                } else {
                    out.append("\(name): ?")
                }
            } else {
                out.append("\(name): down")
            }
            ptr = ifa.ifa_next
        }
        return out
    }

    static func lsLines(_ args: [String]) -> [String] {
        let path = args.first(where: { !$0.hasPrefix("-") }) ?? "."
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: path) else {
            return ["ls: cannot access '\(path)' — negato o inesistente"]
        }
        let out = items.sorted().map { n -> String in
            let full = path.hasSuffix("/") ? path + n : path + "/" + n
            var isDir: ObjCBool = false
            var size = "       -"
            if fm.fileExists(atPath: full, isDirectory: &isDir),
               let attr = try? fm.attributesOfItem(atPath: full), let s = attr[.size] as? Int {
                size = String(format: "%8d", s)
            }
            return "\(size)  \(n)\(isDir.boolValue ? "/" : "")"
        }
        return out.isEmpty ? ["(vuoto)"] : out
    }

    static func catLines(_ args: [String]) -> [String] {
        guard let f = args.first else { return ["cat: manca il file"] }
        guard let s = try? String(contentsOfFile: f, encoding: .utf8) else {
            return ["cat: \(f) — permesso negato o inesistente"]
        }
        return s.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    }

    static var psLines: [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var size = 0
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0 else {
            return ["ps: sysctl negato"]
        }
        var buffer = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride)
        var bsize = size
        guard sysctl(&mib, u_int(mib.count), &buffer, &bsize, nil, 0) == 0 else {
            return ["ps: sysctl negato (2)"]
        }
        return buffer.map { p -> String in
            var pathbuf = [CChar](repeating: 0, count: 2048)
            let r = proc_pidpath_c(p.kp_proc.p_pid, &pathbuf, 2048)
            let path = r > 0 ? String(cString: pathbuf) : "(hidden)"
            return String(format: "%6d  %@", p.kp_proc.p_pid, path)
        }
    }
}

enum ToolRegistry {
    static let appBinDir = "/var/mobile/RedHatSec/bin"
    static let workDir = "/var/mobile/RedHatSec"
    static let sourcesPath = workDir + "/etc/apt/sources.list.d/rhs.list"

    // sorgenti di default: base rootless + repo community tool di sicurezza
    // estendibile a runtime: `repo add <url>` dal terminale
    static let defaultRepos: [String] = [
        "deb https://apt.procurs.us/ iphoneos-arm64/1900 main",
        "deb https://repo.chariz.com/ iphoneos-arm64/1900 main",
        "deb https://havoc.app/ iphoneos-arm64/1900 main",
        "deb https://repo.dylbin.com/ ./",
        "deb https://cydia.invoxiplaygames.com/ ./",
        "deb https://repo.coxxs.net/ ./",
    ]

    static func sources() -> [String] {
        if let s = try? String(contentsOfFile: sourcesPath, encoding: .utf8) {
            let lines = s.split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            if !lines.isEmpty { return lines }
        }
        return defaultRepos
    }

    static func writeSources(_ lines: [String]) -> String? {
        let dir = (sourcesPath as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try lines.joined(separator: "\n").write(toFile: sourcesPath, atomically: true, encoding: .utf8)
            return nil
        } catch {
            // dir owner root (creata via rootd in run precedenti) → scrivo via rootd e ripasso a mobile
            guard RootShell.shared.available else { return "\(error)" }
            let sq: (String) -> String = { $0.replacingOccurrences(of: "'", with: "") }
            var cmd = "mkdir -p '\(sq(dir))' && rm -f '\(sq(sourcesPath))'"
            for l in lines { cmd += " && printf '%s\\n' '\(sq(l))' >> '\(sq(sourcesPath))'" }
            cmd += " && chown -R mobile:mobile '\(sq(workDir))/etc'"
            let r = RootShell.shared.runSync(cmd, timeout: 15)
            if r.exitCode == 0, FileManager.default.fileExists(atPath: sourcesPath) { return nil }
            return "mobile EPERM (\(error)) e rootd write rc=\(r.exitCode)"
        }
    }

    // builtin terminale: repo list | repo add <url> | repo del <kw>
    static func repoCmd(_ args: [String]) -> [String] {
        guard let sub = args.first else { return sources() }
        switch sub {
        case "list":
            return ["sorgenti (\(sourcesPath)):"]
                + sources().map { "  \($0)" }
                + ["estendi con: repo add deb https://<host>/ ./"]
        case "add":
            guard args.count > 1 else { return ["repo add: serve l'URL"] }
            var s = sources()
            var added: [String] = []
            for url in args.dropFirst() {
                let line = url.hasPrefix("deb") ? url : "deb \(url) ./"
                if !s.contains(line) { s.append(line); added.append(line) }
            }
            if let e = writeSources(s) { return ["write rhs.list fallita: \(e)"] }
            return added.isEmpty ? ["già presente"] : ["repo aggiunti:"] + added
        case "del":
            guard args.count > 1 else { return ["repo del: serve la keyword"] }
            let kw = args[1]
            let s = sources().filter { !$0.contains(kw) }
            if let e = writeSources(s) { return ["write rhs.list fallita: \(e)"] }
            return ["rimossi i sorgenti con '\(kw)' (\(s.count) rimasti)"]
        default:
            return ["uso: repo list | repo add <deb-url> | repo del <kw>"]
        }
    }

    static let specs: [ToolSpec] = [
        ToolSpec(name: "nmap", pkg: "nmap", bins: ["nmap"]),
        ToolSpec(name: "tcpdump", pkg: "tcpdump", bins: ["tcpdump"]),
        ToolSpec(name: "aircrack-ng", pkg: "aircrack-ng", bins: ["aircrack-ng", "aireplay-ng", "airodump-ng"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/aircrack-ng_iphoneos-arm64.deb"),
        ToolSpec(name: "socat", pkg: "socat", bins: ["socat"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/socat_iphoneos-arm64.deb"),
        ToolSpec(name: "reaver", pkg: "reaver", bins: ["reaver", "pixiewps"]),
        ToolSpec(name: "mdk3", pkg: "mdk3", bins: ["mdk3"]),
        ToolSpec(name: "yersinia", pkg: "yersinia", bins: ["yersinia"]),
        ToolSpec(name: "ettercap", pkg: "ettercap", bins: ["ettercap"]),
        ToolSpec(name: "hostapd", pkg: "hostapd", bins: ["hostapd"]),
        ToolSpec(name: "killerbee", pkg: "killerbee", bins: ["zbdsniff"]),
        ToolSpec(name: "curl", pkg: "curl", bins: ["curl"]),
        ToolSpec(name: "python3", pkg: "python3", bins: ["python3"]),
        ToolSpec(name: "netcat", pkg: "netcat", bins: ["nc"]),
        ToolSpec(name: "openssh", pkg: "openssh", bins: ["ssh", "scp", "ssh-keygen"]),
        ToolSpec(name: "openssl", pkg: "openssl", bins: ["openssl"]),
        ToolSpec(name: "wget", pkg: "wget", bins: ["wget"]),
    ]

    static func spec(_ tool: String) -> ToolSpec? {
        specs.first { $0.name == tool || $0.bins.contains(tool) }
    }

    static func install(_ tool: String, line: @escaping (String) -> Void, done: @escaping (Bool) -> Void) {
        guard let s = spec(tool) else {
            line("tool non catalogato: \(tool) — apro la ricerca Sileo")
            DispatchQueue.main.async { openSileo(tool, search: true) }
            done(false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            let fm = FileManager.default
            try? fm.createDirectory(atPath: appBinDir, withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: workDir + "/tmp", withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: workDir + "/extracted", withIntermediateDirectories: true)

            let sh = ShellRunner.shared
            let apt = sh.resolve("apt-get")
            let dpkgDeb = sh.resolve("dpkg-deb")

            // PATH 1 — apt root via rootd con sorgenti RHS aggregati (app-owned)
            if RootShell.shared.available {
                let lines = sources()
                if let e = writeSources(lines) {
                    line("[install] write rhs.list fallita: \(e)")
                }
                let chk = RootShell.shared.runSync("ls -la '\(sourcesPath)' && head -2 '\(sourcesPath)'", timeout: 10)
                line("[install] rhs.list: \(chk.stdout.isEmpty ? "MANCANTE/err=" + String(chk.exitCode) : chk.stdout.prefix(120))")
                let opts = "-o Dir::Etc::sourcelist=\(sourcesPath) -o Dir::Etc::sourceparts=-"
                line("[install] apt root via rootd — \(lines.count) sorgenti RHS…")
                let upd = RootShell.shared.runSync("apt-get \(opts) update", timeout: 240)
                let uout = (upd.stderr.isEmpty ? upd.stdout : upd.stderr)
                line(String(uout.suffix(500)))
                let r = RootShell.shared.runSync("apt-get \(opts) install -y --allow-unauthenticated \(s.pkg)", timeout: 300)
                let out = (r.stdout.isEmpty ? r.stderr : r.stdout)
                line(String(out.suffix(400)))
                if r.exitCode == 0, s.bins.first(where: { sh.resolve($0) != nil }) != nil {
                    line("[install] \(tool) installato ROOT in /var/jb ✓ — ridigita il comando")
                    done(true)
                    return
                }
                line("[install] apt RHS fallito (exit=\(r.exitCode)) — se il tool è in un altro repo: `repo add deb https://<host>/ ./`")

                // PATH 1.5 — .deb locale: download + dpkg -i via rootd
                if let url = s.debURL {
                    line("[install] .deb locale: \(url)…")
                    let d = RootShell.shared.runSync("curl -fSL --max-time 180 -o \(workDir)/tmp/\(s.pkg).deb '\(url)' && dpkg -i \(workDir)/tmp/\(s.pkg).deb", timeout: 300)
                    let dout = (d.stdout.isEmpty ? d.stderr : d.stdout)
                    line(String(dout.suffix(400)))
                    if d.exitCode == 0, s.bins.first(where: { sh.resolve($0) != nil }) != nil {
                        line("[install] \(tool) installato da .deb ✓ — ridigita il comando")
                        done(true)
                        return
                    }
                }
            }

            // PATH 2 — userland: download + estrazione in appBinDir
            if apt != nil && dpkgDeb != nil {
                line("[install] apt fetch \(s.pkg)…")
                let fetch = sh.run("sh", args: ["-c",
                    "cd \(workDir)/tmp && apt-get -o Dir::Cache::archives=\(workDir)/tmp -o Dir::State::lists=/var/jb/var/lib/apt/lists download \(s.pkg) 2>&1; echo \"fetch-exit=$?\""], timeout: 180)
                line(fetch.stdout.isEmpty ? fetch.stderr : fetch.stdout)
                let extract = sh.run("sh", args: ["-c",
                    "cd \(workDir)/tmp && ls *.deb >/dev/null 2>&1 && for d in *.deb; do dpkg-deb -x \"\(workDir)/tmp/$d\" \(workDir)/extracted; done && cp \(workDir)/extracted/var/jb/usr/bin/* \(appBinDir)/ 2>/dev/null; cp \(workDir)/extracted/usr/bin/* \(appBinDir)/ 2>/dev/null; cp \(workDir)/extracted/usr/local/bin/* \(appBinDir)/ 2>/dev/null; chmod 755 \(appBinDir)/* 2>/dev/null; rm -f \(workDir)/tmp/*.deb; true"], timeout: 120)
                let found = s.bins.first { sh.resolve($0) != nil } != nil
                if found {
                    line("[install] \(tool) estratto in \(appBinDir) ✓ — exec senza root")
                    done(true)
                    return
                }
                line("[install] apt path fallito (app=mobile, apt vuole root per lock/index) → Sileo")
            } else {
                line("[install] apt/dpkg-deb non presenti → Sileo")
            }
            line("[sileo] tocca GET/INSTALLA su \(s.pkg) — root via helper di Sileo; poi ridigita il comando")
            DispatchQueue.main.async {
                openSileo(s.pkg)
            }
            done(false)
        }
    }

    static func openSileo(_ pkg: String, search: Bool = false) {
        guard let url = URL(string: search ? "sileo://search/\(pkg)" : "sileo://package/\(pkg)") else { return }
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
}
