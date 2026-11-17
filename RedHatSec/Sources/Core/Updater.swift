import Foundation
import UIKit
import CryptoKit

// auto-updater: release GitHub tag `tipa` (asset latest.json + RedHatSec-<tag>.tipa)
// il confronto è buildTag compilato vs remoto; install via TrollStore (apple-magnifier://install?file=)
enum Updater {
    static let repo = "vibecoder-lover/redhatsec"

    struct Info: Equatable {
        let build: String
        let date: String
        let fileURL: URL
        var sha256: String? = nil
    }

    static var current: String { ToolRegistry.buildTag }

    // il tag arriva dalla rete: niente quote/slash/newline in un comando root o in un path
    private static func safeBuild(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count <= 64,
              t.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else { return nil }
        return t
    }

    private static func shq(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func latest() async -> Info? {
        guard let rel = URL(string: "https://api.github.com/repos/\(repo)/releases/tags/tipa") else { return nil }
        var req = URLRequest(url: rel)
        req.timeoutInterval = 20
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let assets = json["assets"] as? [[String: Any]] else { return nil }
        for a in assets {
            guard let name = a["name"] as? String, name == "latest.json",
                  let lu = (a["browser_download_url"] as? String).flatMap(URL.init(string:)) else { continue }
            var req = URLRequest(url: lu)
            req.timeoutInterval = 20
            guard let (jdata, jresp) = try? await URLSession.shared.data(for: req),
                  (jresp as? HTTPURLResponse)?.statusCode == 200,
                  let j = try? JSONSerialization.jsonObject(with: jdata) as? [String: Any],
                  let rawBuild = j["build"] as? String, let build = safeBuild(rawBuild),
                  let file = j["file"] as? String,
                  file.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil,
                  let date = j["date"] as? String,
                  let furl = URL(string: "https://github.com/\(repo)/releases/download/tipa/\(file)") else { continue }
            return Info(build: build, date: date, fileURL: furl, sha256: j["sha256"] as? String)
        }
        return nil
    }

    static func check() async -> (info: Info, update: Bool)? {
        guard let info = await latest() else { return nil }
        return (info, info.build != current)
    }

    // Flusso GARANTITO (niente URL scheme): download nel container → share sheet
    // "Open in TrollStore". TrollStore esporta l'UTI com.opa334.trollstore.tipa
    // e TSSceneDelegate prende i file:// direttamente (presentInstallationAlert).
    static var dic: UIDocumentInteractionController?

    static func downloadAndInstall(_ info: Info) async -> String {
        let fm = FileManager.default
        guard let build = safeBuild(info.build) else { return "build tag non valido — update rifiutato" }
        // nome FISSO: niente path traversal da un tag remoto
        let dest = (NSTemporaryDirectory() as NSString).appendingPathComponent("RedHatSecUpdate.tipa")
        try? fm.removeItem(atPath: dest)
        guard let (tmp, resp) = try? await URLSession.shared.download(from: info.fileURL),
              (resp as? HTTPURLResponse)?.statusCode == 200 else {
            return "download fallito (rete?)"
        }
        do {
            try fm.moveItem(at: tmp, to: URL(fileURLWithPath: dest))
        } catch {
            return "move fallita: \(error.localizedDescription)"
        }
        // integrità: sha256 da latest.json se presente, altrimenti sanity (un .tipa è uno zip)
        if let want = info.sha256?.lowercased(), !want.isEmpty {
            guard let blob = try? Data(contentsOf: URL(fileURLWithPath: dest)) else {
                return "lettura tipa fallita"
            }
            let got = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
            guard got == want else { return "hash mismatch — file scartato (atteso \(want.prefix(12))…)" }
        } else {
            guard let fh = FileHandle(forReadingAtPath: dest),
                  let magic = try? fh.read(upToCount: 2), magic == Data([0x50, 0x4b]) else {
                return "file non valido (non è un tipa/zip) — scartato"
            }
            try? fh.close()
        }
        // VIA A (rootd): copia in /var/jb/tmp e magnifier url=file:// — TrollStore
        // (TSInstallationController) NON valida lo scheme: NSURLSessionDownloadTask
        // copia anche i file:// (TrollStore è root, legge /var/jb/tmp)
        let jbPath = "/var/jb/tmp/rhs.tipa"
        let cpCmd = "rm -f \(shq(jbPath)); cp \(shq(dest)) \(shq(jbPath)) && chmod 644 \(shq(jbPath))"
        // rootd può bloccare fino a 30s: fuori dal main actor
        let cp = await Task.detached(priority: .userInitiated) {
            RootShell.shared.runSync(cpCmd, timeout: 30)
        }.value
        if cp.exitCode == 0 {
            await MainActor.run {
                if let u = URL(string: "apple-magnifier://install?url=file://\(jbPath)") {
                    UIApplication.shared.open(u)
                }
            }
            return "install via TrollStore avviata (\(build)) — conferma nell'alert"
        }
        // VIA B (rootd giù): share sheet DIC
        await MainActor.run {
            let d = UIDocumentInteractionController(url: URL(fileURLWithPath: dest))
            d.uti = "com.opa334.trollstore.tipa"
            dic = d   // DIC va trattenuta, altrimenti il pannello chiude subito
            if let scene = UIApplication.shared.connectedScenes
                .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
               let win = scene.windows.first(where: { $0.isKeyWindow }) {
                d.presentOpenInMenu(from: win.bounds, in: win, animated: true)
            }
        }
        return "tipa pronto (\(info.build)) — tocca \"TrollStore\" nel pannello e conferma (rootd giù)"
    }
}
// build trigger 28c1cb6-cancelled
