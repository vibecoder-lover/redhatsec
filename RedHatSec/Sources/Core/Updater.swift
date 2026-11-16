import Foundation
import UIKit

// auto-updater: release GitHub tag `tipa` (asset latest.json + RedHatSec-<tag>.tipa)
// il confronto è buildTag compilato vs remoto; install via TrollStore (apple-magnifier://install?file=)
enum Updater {
    static let repo = "vibecoder-lover/redhatsec"

    struct Info: Equatable {
        let build: String
        let date: String
        let fileURL: URL
    }

    static var current: String { ToolRegistry.buildTag }

    static func latest() async -> Info? {
        guard let rel = URL(string: "https://api.github.com/repos/\(repo)/releases/tags/tipa"),
              let (data, resp) = try? await URLSession.shared.data(from: rel),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let assets = json["assets"] as? [[String: Any]] else { return nil }
        for a in assets {
            guard let name = a["name"] as? String, name == "latest.json",
                  let lu = (a["browser_download_url"] as? String).flatMap(URL.init(string:)),
                  let (jdata, _) = try? await URLSession.shared.data(from: lu),
                  let j = try? JSONSerialization.jsonObject(with: jdata) as? [String: Any],
                  let build = j["build"] as? String,
                  let file = j["file"] as? String,
                  let date = j["date"] as? String,
                  let furl = URL(string: "https://github.com/\(repo)/releases/download/tipa/\(file)") else { continue }
            return Info(build: build, date: date, fileURL: furl)
        }
        return nil
    }

    static func check() async -> (info: Info, update: Bool)? {
        guard let info = await latest() else { return nil }
        return (info, info.build != current)
    }

    // TrollStore (TSSceneDelegate.m): apple-magnifier://install?url=<https> →
    // TROLLSTORE scarica e presenta l'install lui stesso. Niente file locali.
    static func downloadAndInstall(_ info: Info) async -> String {
        var comps = URLComponents()
        comps.scheme = "apple-magnifier"
        comps.host = "install"
        comps.queryItems = [URLQueryItem(name: "url", value: info.fileURL.absoluteString)]
        guard let ts = comps.url else {
            return "url magnifier non costruibile"
        }
        let ok: Bool = await withCheckedContinuation { c in
            UIApplication.shared.open(ts, options: [:]) { c.resume(returning: $0) }
        }
        return ok
            ? "TrollStore aperto — scarica e installa \(info.build), conferma lì"
            : "TrollStore non risponde all'URL — installa a mano dal release GitHub"
    }
}
// build trigger 28c1cb6-cancelled
