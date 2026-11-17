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
    static let ncShimPath = "/var/jb/usr/local/bin/nc"

    // Shim `nc`: il netcat del device (BSD/busybox) non accetta le flag fuse tipo
    // `-lvnp 4444`. Il wrapper spezza i flag e li rimanda al binario vero:
    //   nc -lvnp 4444  ->  nc -l -v -n -p 4444
    static let ncShimScript: String = """
    #!/bin/sh
    # rhs nc shim v2: normalizza flag fuse (-lvnp 4444) e sceglie la sintassi
    # di listen accettata dal netcat locale (BSD/ncat: porta posizionale; GNU/busybox: -p)
    REAL=""
    for c in /var/jb/usr/bin/nc /var/jb/bin/nc /usr/bin/nc /bin/nc /var/jb/usr/local/bin/nc.real; do
      if [ -x "$c" ]; then REAL="$c"; break; fi
    done
    if [ -z "$REAL" ]; then
      echo "nc: netcat non installato - usa: install netcat" >&2
      exit 127
    fi

    OLDIFS=$IFS
    IFS="
    "
    ARGS=""
    listen=0
    plist=0
    port=""
    skip=0
    add() { if [ -z "$ARGS" ]; then ARGS="$1"; else ARGS="$ARGS
    $1"; fi; }
    for a in "$@"; do
      if [ "$skip" = 1 ]; then port="$a"; skip=0; continue; fi
      case "$a" in
        --*) add "$a" ;;
        -?*)
          flags=${a#-}
          while [ -n "$flags" ]; do
            c=${flags%"${flags#?}"}
            flags=${flags#?}
            case "$c" in
              l) listen=1; add "-l" ;;
              p) plist=1; if [ -n "$flags" ]; then port="$flags"; flags=""; else skip=1; fi ;;
              v|n|z|u|k|d|D|r|t|b|N|4|6|h) add "-$c" ;;
              *) add "-$c$flags"; flags="" ;;
            esac
          done ;;
        *)
          if [ "$listen" = 1 ] && [ -z "$port" ]; then port="$a"; else add "$a"; fi ;;
      esac
    done
    set -- $ARGS
    IFS=$OLDIFS

    if [ "$listen" = 1 ]; then
      if [ -z "$port" ]; then
        echo "nc shim: listen senza porta" >&2
        exit 1
      fi
      # probe di sintassi su una porta libera: BSD/ncat vs GNU/busybox
      probe_listen() {
        "$REAL" "$@" >/dev/null 2>&1 &
        tp=$!
        sleep 0.4
        if kill -0 "$tp" 2>/dev/null; then
          kill "$tp" 2>/dev/null
          wait "$tp" 2>/dev/null
          return 0
        fi
        wait "$tp" 2>/dev/null
        return 1
      }
      PP=55321
      if probe_listen "$@" -p "$PP"; then
        exec "$REAL" "$@" -p "$port"
      fi
      if probe_listen "$@" "$PP"; then
        exec "$REAL" "$@" "$port"
      fi
      exec "$REAL" "$@" "$port"
    fi

    if [ "$plist" = 1 ] && [ -n "$port" ]; then
      set -- "$@" -p "$port"
    fi
    exec "$REAL" "$@"
    """

    static func ensureNetcatShimIfNeeded() {
        // riscrive sempre lo shim (v2): gli update dell'app devono sostituire la versione vecchia
        DispatchQueue.global(qos: .utility).async {
            let nc = RootShell.shared.runSync("command -v nc >/dev/null 2>&1 && echo NC", timeout: 10)
            guard nc.stdout.contains("NC") else { return }
            ensureNetcatShim()
        }
    }

    static func ensureNetcatShim() {
        guard RootShell.shared.available else { return }
        // printf %b: script single-line (rootd legge UNA riga) senza dipendere da base64
        let body = ncShimScript
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\n", with: "\\n")
        let cmd = "mkdir -p /var/jb/usr/local/bin && "
            + "printf '%b' '\(body)' > \(ncShimPath) && chmod 755 \(ncShimPath) "
            + "&& echo NC-SHIM-OK"
        DispatchQueue.global(qos: .utility).async {
            _ = RootShell.shared.runSync(cmd, timeout: 20)
        }
    }

    // sorgenti di default: Procursus rootless (suite 1900 = arch iphoneos-arm64, iOS16 Dopamine)
    // estendibile a runtime: `repo add <url>` dal terminale; `repo reset` riparte da qui
    static let defaultRepos: [String] = [
        "deb https://apt.procurs.us/ 1900 main",
        "deb https://apt.procurs.us/ 2000 main",
    ]

    static func sources() -> [String] {
        // se il file esiste lo rispetto anche se vuoto (repo del intenzionale);
        // i default si usano solo quando il file è assente
        guard FileManager.default.fileExists(atPath: sourcesPath) else { return defaultRepos }
        let s = (try? String(contentsOfFile: sourcesPath, encoding: .utf8)) ?? ""
        return s.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
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
            let sq: (String) -> String = { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
            var cmd = "mkdir -p \(sq(dir)) && rm -f \(sq(sourcesPath))"
            for l in lines { cmd += " && printf '%s\\n' \(sq(l)) >> \(sq(sourcesPath))" }
            cmd += " && chown -R mobile:mobile \(sq(workDir))/etc"
            // main thread: non bloccare la UI per un runSync fino a 15s
            if Thread.isMainThread {
                DispatchQueue.global(qos: .utility).async { _ = RootShell.shared.runSync(cmd, timeout: 15) }
                return "scrittura rhs.list via rootd in background — riprova tra 1s"
            }
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
        ToolSpec(name: "ettercap", pkg: "ettercap", bins: ["ettercap"],
                 debURL: "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/ettercap_iphoneos-arm64.deb"),
        ToolSpec(name: "hcxdumptool", pkg: "hcxdumptool", bins: ["hcxdumptool"]),
        ToolSpec(name: "hcxpcapngtool", pkg: "hcxtools", bins: ["hcxpcapngtool"]),
        ToolSpec(name: "killerbee", pkg: "killerbee", bins: ["zbdsniff"]),
        ToolSpec(name: "curl", pkg: "curl", bins: ["curl"]),
        ToolSpec(name: "python3", pkg: "python3", bins: ["python3"]),
        ToolSpec(name: "netcat", pkg: "netcat", bins: ["nc"]),
        ToolSpec(name: "util-linux", pkg: "util-linux", bins: ["script"]),
        ToolSpec(name: "openssh", pkg: "openssh", bins: ["ssh", "scp", "ssh-keygen"]),
        ToolSpec(name: "openssl", pkg: "openssl", bins: ["openssl"]),
        ToolSpec(name: "wget", pkg: "wget", bins: ["wget"]),
        ToolSpec(name: "dpkg", pkg: "dpkg", bins: ["dpkg", "dpkg-deb"]),
        ToolSpec(name: "apt", pkg: "apt", bins: ["apt", "apt-get"]),
    ]

    static func spec(_ tool: String) -> ToolSpec? {
        specs.first { $0.name == tool || $0.bins.contains(tool) }
    }

    // vero se almeno uno dei binari è nel PATH della sh root
    static func rootHas(_ bins: [String]) -> Bool {
        guard !bins.isEmpty else { return false }
        let q = bins.map { "command -v \($0) >/dev/null 2>&1" }.joined(separator: " || ")
        return RootShell.shared.runSync(q, timeout: 15).exitCode == 0
    }

    static func install(_ tool: String, line: @escaping (String) -> Void, done: @escaping (Bool) -> Void) {
        guard let s = spec(tool) else {
            line("tool non catalogato: \(tool) — apro la ricerca Sileo")
            DispatchQueue.main.async { openSileo(tool, search: true) }
            done(false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            // già installato: la detection app può fallire, quindi verifica dal root
            if rootHas(s.bins) {
                line("[install] \(tool) già presente nel bootstrap ✓")
                ShellRunner.shared.rescanTools()
                if s.bins.contains("nc") { ensureNetcatShim() }
                done(true)
                return
            }
            let fm = FileManager.default
            try? fm.createDirectory(atPath: appBinDir, withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: workDir + "/tmp", withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: workDir + "/extracted", withIntermediateDirectories: true)

            let sh = ShellRunner.shared
            let apt = sh.resolve("apt-get")
            let dpkgDeb = sh.resolve("dpkg-deb")

            // PATH 1 — apt root via rootd con sorgenti RHS aggregati (app-owned)
            let st = RootShell.shared.runSync("echo rhs-rootd-ok", timeout: 12)
            line("[install] rootd: \(st.exitCode == 0 ? "ok" : "DOWN (exit=\(st.exitCode)) \(st.stderr.prefix(80))")")
            if st.exitCode == 0 {
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
                if r.exitCode == 0, (s.bins.first(where: { sh.resolve($0) != nil }) != nil || rootHas(s.bins)) {
                    sh.rescanTools()
                    if s.bins.contains("nc") { ensureNetcatShim() }
                    line("[install] \(tool) installato ROOT in /var/jb ✓ — ridigita il comando")
                    done(true)
                    return
                }
                line("[install] apt RHS fallito (exit=\(r.exitCode)) — se il tool è in un altro repo: `repo add deb https://<host>/ ./`")

                // PATH 1.5 — .deb locale: bootstrap dpkg se assente + dpkg -i; fallback estrazione tar (bsdtar legge l'ar)
                // se lo spec non ha debURL, prova il nome convenzionale nella release (future crossbuild)
                let debUrl = s.debURL ?? "https://github.com/vibecoder-lover/redhatsec/releases/download/debs/\(s.pkg)_iphoneos-arm64.deb"
                line("[install] .deb locale: \(debUrl)…")
                let tmpDeb = "\(workDir)/tmp/\(s.pkg).deb"
                let script = "rm -f \(tmpDeb); "
                  + "command -v dpkg >/dev/null 2>&1 || apt-get install -y --allow-unauthenticated dpkg; "
                  + "curl -fSL --max-time 180 -o \(tmpDeb) '\(debUrl)' || { echo CURL-FAIL; exit 1; }; "
                  + "if dpkg -i \(tmpDeb); then echo DEB-OK; else "
                  + "rm -rf \(workDir)/tmp/x; mkdir -p \(workDir)/tmp/x; cd \(workDir)/tmp/x && "
                  + "(tar -xf ../\(s.pkg).deb 2>/dev/null || exit 1) && "
                  + "(if [ -f data.tar.gz ]; then tar xzf data.tar.gz -C /; "
                  + "elif [ -f data.tar.xz ]; then tar xJf data.tar.xz -C /; "
                  + "else tar xf data.tar.* -C /; fi) && echo TAR-OK; fi"
                let d = RootShell.shared.runSync(script, timeout: 300)
                let dout = (d.stdout.isEmpty ? d.stderr : d.stdout)
                line(String(dout.suffix(400)))
                if d.exitCode == 0, (s.bins.first(where: { sh.resolve($0) != nil }) != nil || rootHas(s.bins)) {
                    sh.rescanTools()
                    if s.bins.contains("nc") { ensureNetcatShim() }
                    line("[install] \(tool) installato da .deb ✓ — ridigita il comando")
                    done(true)
                    return
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
                let found = s.bins.first { sh.resolve($0) != nil } != nil || rootHas(s.bins)
                if found {
                    sh.rescanTools()
                    if s.bins.contains("nc") { ensureNetcatShim() }
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
