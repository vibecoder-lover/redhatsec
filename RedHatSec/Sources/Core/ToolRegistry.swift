import Foundation
import UIKit

struct ToolSpec {
    let name: String
    let pkg: String
    let bins: [String]
    var debURL: String? = nil
}

enum BuiltinExec {
    // SOLO comandi app-meta (non shell). TUTTO il resto va alla sh root reale
    // della sessione rootd persistente — niente finti, niente simulazioni.
    static func exec(_ parts: [String]) -> [String]? {
        guard let head = parts.first else { return nil }
        switch head {
        case "help": return helpLines
        case "spawntest": return ShellRunner.shared.probeSpawn()
        case "repo": return ToolRegistry.repoCmd(Array(parts.dropFirst()))
        default: return nil
        }
    }

    static let helpLines: [String] = [
        "shell root REALE: rootd (launchd inetd :4444) → sh uid=0 persistente",
        "  ls cat cd echo whoami id uname env df ps ifconfig pwd grep …",
        "  pwd/cd/export/env persistono tra i comandi (stessa sh viva)",
        "comandi app:",
        "  install <tool>            → auto-install .deb da release debs (rootd → dpkg)",
        "  repo list/add/del/reset   → sorgenti apt RHS (\(ToolRegistry.sourcesPath))",
        "  spawntest                 → diagnostica spawn persona + rootd + entitlements",
        "  clear · exit              → UI (exit chiude la sessione rootd)",
        "tutto il resto: exec reale uid=0 nella sessione viva",
    ]
}

enum ToolRegistry {
    static let buildTag = "b6-dev"
    static let appBinDir = "/var/mobile/RedHatSec/bin"
    static let workDir = "/var/mobile/RedHatSec"
    static let sourcesPath = workDir + "/etc/apt/sources.list.d/rhs.list"

    // sorgenti di default: Procursus rootless (suite 1900 = arch iphoneos-arm64, iOS16 Dopamine)
    // estendibile a runtime: `repo add <url>` dal terminale; `repo reset` riparte da qui
    static let defaultRepos: [String] = [
        "deb https://apt.procurs.us/ 1900 main",
        "deb https://apt.procurs.us/ 2000 main",
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
            if r.exitCode == 0 { return nil }
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
                + ["estendi con: repo add deb https://<host>/ ./ — reset: repo reset"]
        case "reset":
            if let e = writeSources(defaultRepos) { return ["write rhs.list fallita: \(e)"] }
            return ["sorgenti ripristinate:"] + defaultRepos.map { "  \($0)" }
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
            return ["uso: repo list | repo add <deb-url> | repo del <kw> | repo reset"]
        }
    }

    static let specs: [ToolSpec] = [
        ToolSpec(name: "nmap", pkg: "nmap", bins: ["nmap"]),
        ToolSpec(name: "tcpdump", pkg: "tcpdump", bins: ["tcpdump"]),
        ToolSpec(name: "hping3", pkg: "hping", bins: ["hping3"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/hping3_iphoneos-arm64.deb"),
        ToolSpec(name: "aircrack-ng", pkg: "aircrack-ng", bins: ["aircrack-ng", "aireplay-ng", "airodump-ng"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/aircrack-ng_iphoneos-arm64.deb"),
        ToolSpec(name: "socat", pkg: "socat", bins: ["socat"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/socat_iphoneos-arm64.deb"),
        ToolSpec(name: "reaver", pkg: "reaver", bins: ["reaver", "wash"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/reaver_iphoneos-arm64.deb"),
        ToolSpec(name: "pixiewps", pkg: "pixiewps", bins: ["pixiewps"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/pixiewps_iphoneos-arm64.deb"),
        ToolSpec(name: "mdk3", pkg: "mdk3", bins: ["mdk3"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/mdk3_iphoneos-arm64.deb"),
        ToolSpec(name: "yersinia", pkg: "yersinia", bins: ["yersinia"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/yersinia_iphoneos-arm64.deb"),
        ToolSpec(name: "hostapd", pkg: "hostapd", bins: ["hostapd"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/hostapd_iphoneos-arm64.deb"),
        ToolSpec(name: "ettercap", pkg: "ettercap", bins: ["ettercap"]),
        ToolSpec(name: "killerbee", pkg: "killerbee", bins: ["zbdsniff"]),
        ToolSpec(name: "curl", pkg: "curl", bins: ["curl"]),
        ToolSpec(name: "python3", pkg: "python3", bins: ["python3"]),
        ToolSpec(name: "netcat", pkg: "netcat", bins: ["nc"]),
        ToolSpec(name: "openssh", pkg: "openssh", bins: ["ssh", "scp", "ssh-keygen"]),
        ToolSpec(name: "openssl", pkg: "openssl", bins: ["openssl"]),
        ToolSpec(name: "wget", pkg: "wget", bins: ["wget"]),
        ToolSpec(name: "dpkg", pkg: "dpkg", bins: ["dpkg", "dpkg-deb"]),
        ToolSpec(name: "apt", pkg: "apt", bins: ["apt", "apt-get"]),
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
                let st = RootShell.shared.runSync("echo rhs-rootd-ok", timeout: 15)
                line("[install] rootd: \(st.exitCode == 0 ? "ok" : "DOWN (exit=\(st.exitCode)) \(st.stderr.prefix(80))")")
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

                // PATH 1.5 — .deb locale: bootstrap dpkg se assente + dpkg -i; fallback estrazione tar (bsdtar legge l'ar)
                if let url = s.debURL {
                    line("[install] .deb locale: \(url)…")
                    let script = "command -v dpkg >/dev/null 2>&1 || apt-get install -y --allow-unauthenticated dpkg; curl -fSL --max-time 180 -o \(workDir)/tmp/\(s.pkg).deb '\(url)' || echo CURL-FAIL; if dpkg -i \(workDir)/tmp/\(s.pkg).deb; then echo DEB-OK; elif command -v tar >/dev/null 2>&1; then rm -rf \(workDir)/tmp/x; mkdir -p \(workDir)/tmp/x; cd \(workDir)/tmp/x && tar -xf ../\(s.pkg).deb 2>/dev/null && tar xzf data.tar.gz -C / && echo TAR-OK; fi"
                    let d = RootShell.shared.runSync(script, timeout: 300)
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
