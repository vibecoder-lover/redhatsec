import Foundation
import UIKit

struct ToolSpec {
    let name: String
    let pkg: String
    let bins: [String]
}

enum ToolRegistry {
    static let appBinDir = "/var/mobile/RedHatSec/bin"
    static let workDir = "/var/mobile/RedHatSec"

    static let specs: [ToolSpec] = [
        ToolSpec(name: "nmap", pkg: "nmap", bins: ["nmap"]),
        ToolSpec(name: "tcpdump", pkg: "tcpdump", bins: ["tcpdump"]),
        ToolSpec(name: "aircrack-ng", pkg: "aircrack-ng", bins: ["aircrack-ng", "aireplay-ng", "airodump-ng"]),
        ToolSpec(name: "reaver", pkg: "reaver", bins: ["reaver", "pixiewps"]),
        ToolSpec(name: "mdk3", pkg: "mdk3", bins: ["mdk3"]),
        ToolSpec(name: "yersinia", pkg: "yersinia", bins: ["yersinia"]),
        ToolSpec(name: "ettercap", pkg: "ettercap", bins: ["ettercap"]),
        ToolSpec(name: "hostapd", pkg: "hostapd", bins: ["hostapd"]),
        ToolSpec(name: "killerbee", pkg: "killerbee", bins: ["zbdsniff"]),
        ToolSpec(name: "curl", pkg: "curl", bins: ["curl"]),
        ToolSpec(name: "python3", pkg: "python3", bins: ["python3"]),
        ToolSpec(name: "netcat", pkg: "netcat", bins: ["nc"]),
    ]

    static func spec(_ tool: String) -> ToolSpec? {
        specs.first { $0.name == tool || $0.bins.contains(tool) }
    }

    static func install(_ tool: String, line: @escaping (String) -> Void, done: @escaping (Bool) -> Void) {
        guard let s = spec(tool) else {
            line("tool non catalogato: \(tool) — cerco su Sileo")
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

            if apt != nil && dpkgDeb != nil {
                line("[install] fetch \(s.pkg)…")
                let fetch = sh.run("sh", args: ["-c",
                    "cd \(workDir)/tmp && apt-get download \(s.pkg) 2>&1"], timeout: 180)
                line(fetch.stdout.isEmpty ? fetch.stderr : fetch.stdout)
                let extract = sh.run("sh", args: ["-c",
                    "cd \(workDir)/tmp && ls *.deb >/dev/null 2>&1 && for d in *.deb; do dpkg-deb -x \"\(workDir)/tmp/$d\" \(workDir)/extracted; done && cp \(workDir)/extracted/var/jb/usr/bin/* \(appBinDir)/ 2>/dev/null; cp \(workDir)/extracted/usr/bin/* \(appBinDir)/ 2>/dev/null; cp \(workDir)/extracted/usr/local/bin/* \(appBinDir)/ 2>/dev/null; chmod 755 \(appBinDir)/* 2>/dev/null; rm -f \(workDir)/tmp/*.deb; true"], timeout: 120)
                line(extract.stdout + " " + extract.stderr)
                let found = s.bins.first { sh.resolve($0) != nil } != nil
                if found {
                    line("[install] \(tool) pronto ✓")
                    done(true)
                    return
                }
                line("[install] estrazione fallita — fallback Sileo")
            } else {
                line("[install] apt/dpkg-deb non disponibili — fallback Sileo")
            }
            done(false)
            DispatchQueue.main.async {
                openSileo(s.pkg)
            }
        }
    }

    static func openSileo(_ pkg: String) {
        guard let url = URL(string: "sileo://package/\(pkg)") else { return }
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
}
