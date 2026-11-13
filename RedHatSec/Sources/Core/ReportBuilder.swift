import Foundation
import UIKit

enum ReportBuilder {
    static var lastHTML: URL?
    static var lastPDF: URL?

    private static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    private static func sevColor(_ s: String) -> String {
        switch s {
        case "critical": return "#EE0000"
        case "high": return "#FF453A"
        case "medium": return "#FFB020"
        case "low": return "#4DA6FF"
        default: return "#8A8A93"
        }
    }

    static func html(_ r: Report) -> String {
        var counts: [Sev: Int] = [:]
        for f in r.findings { counts[f.sev, default: 0] += 1 }
        let order: [Sev] = [.critical, .high, .medium, .low, .info]

        var body = ""
        for f in r.findings.sorted(by: { $0.sev < $1.sev }) {
            let repro = f.repro.map { "<li>\(esc($0))</li>" }.joined()
            body += """
            <section class="f">
              <div class="head"><span class="dot" style="background:\(sevColor(f.sev.rawValue))"></span>
                <h2>\(esc(f.title))</h2>
                <span class="chip" style="border-color:\(sevColor(f.sev.rawValue));color:\(sevColor(f.sev.rawValue))">\(f.sev.rawValue.uppercased()) · CVSS \(f.cvss)</span></div>
              <p class="meta">target: \(esc(f.target)) · ATT&amp;CK \(esc(f.attack)) · <code>\(esc(f.cvssVec))</code></p>
              <h3>Evidence</h3><pre>\(esc(f.evidence))</pre>
              <h3>Reproduction</h3><ul>\(repro)</ul>
              <h3>Impact</h3><p>\(esc(f.impact))</p>
              <h3>Remediation</h3><p>\(esc(f.remediation))</p>
            </section>
            """
        }

        let execSummary = order.map { "\($0.rawValue.capitalized): \(counts[$0] ?? 0)" }.joined(separator: " · ")

        return """
        <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body{background:#0A0A0C;color:#EAEAEA;font:15px/1.55 -apple-system,sans-serif;margin:0;padding:24px}
          h1{font-size:26px;margin:0 0 4px} .sub{color:#8A8A93;font-size:13px}
          .bar{height:3px;background:linear-gradient(90deg,#EE0000,#FFB020);border-radius:2px;margin:16px 0 24px}
          .sum{background:#141418;border:1px solid #ffffff12;border-radius:14px;padding:14px 16px;margin-bottom:20px}
          .f{background:#141418;border:1px solid #ffffff10;border-radius:16px;padding:16px;margin-bottom:16px}
          .head{display:flex;align-items:center;gap:10px;flex-wrap:wrap} .head h2{font-size:17px;margin:0;flex:1}
          .dot{width:10px;height:10px;border-radius:5px} .chip{font-size:11px;border:1px solid;border-radius:8px;padding:2px 8px}
          .meta{color:#8A8A93;font-size:12px;margin:6px 0 0} code{font-size:11px;color:#4DA6FF}
          h3{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#8A8A93;margin:14px 0 4px}
          pre{background:#0A0A0C;border:1px solid #ffffff10;border-radius:10px;padding:10px;font:11px/1.45 ui-monospace,Menlo;white-space:pre-wrap;word-break:break-word;color:#9EE493;max-height:340px;overflow:auto}
          ul{margin:4px 0;padding-left:18px} li{margin:2px 0} p{margin:4px 0}
        </style></head><body>
        <h1>RedHat Sec — IoT Assessment Report</h1>
        <p class="sub">\(esc(r.title)) · generato \(DateFormatter.localizedString(from: r.date, dateStyle: .long, timeStyle: .short)) · \(r.targets.count) target · \(r.findings.count) finding</p>
        <div class="bar"></div>
        <div class="sum"><b>Executive summary</b><br>\(execSummary)<br>
        <span class="sub">Scope: dispositivo iOS jailbroken 16.1.1, orchestrazione vettori IoT (Wi-Fi / BLE / NFC / Zigbee / Net). Journal: audit_journal.txt</span></div>
        \(body.isEmpty ? "<p class='sub'>Nessun finding — nessun target esposto rilevato.</p>" : body)
        </body></html>
        """
    }

    @discardableResult
    static func write(_ r: Report) -> URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let f = docs.appendingPathComponent("redhatsec-report.html")
        try? html(r).write(to: f, atomically: true, encoding: .utf8)
        lastHTML = f
        return f
    }

    @discardableResult
    static func pdf(_ r: Report) -> URL {
        let pageRect = CGRect(x: 0, y: 0, width: 595, height: 842) // A4
        let margin: CGFloat = 44
        let format = UIGraphicsPDFRendererFormat()
        let renderer = UIGraphicsPDFRenderer(bounds: pageRect, format: format)
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = docs.appendingPathComponent("redhatsec-report.pdf")
        try? renderer.writePDF(to: url) { (ctx: UIGraphicsPDFRendererContext) in
            ctx.beginPage()
            var y: CGFloat = margin
            func text(_ s: String, font: UIFont, color: UIColor, size: CGFloat = 300) {
                let para = NSMutableParagraphStyle(); para.lineSpacing = 3
                let attr: [NSAttributedString.Key: Any] = [.font: font, .paragraphStyle: para,
                                                           .foregroundColor: color]
                let w = pageRect.width - margin * 2
                let h = (s as NSString).boundingRect(with: CGSize(width: w, height: size),
                                                     options: [.usesLineFragmentOrigin, .usesFontLeading],
                                                     attributes: attr, context: nil).height
                (s as NSString).draw(in: CGRect(x: margin, y: y, width: w, height: h + 4), withAttributes: attr)
                y += h + 10
            }
            func newPageIfNeeded(_ needed: CGFloat) {
                if y + needed > pageRect.height - margin { ctx.beginPage(); y = margin }
            }
            text("RedHat Sec — IoT Assessment Report", font: .systemFont(ofSize: 22, weight: .bold), color: .black, size: 60)
            text(r.title, font: .systemFont(ofSize: 11), color: .darkGray)
            text("Targets: \(r.targets.count)   Findings: \(r.findings.count)", font: .systemFont(ofSize: 12, weight: .semibold), color: .black)

            for f in r.findings.sorted(by: { $0.sev < $1.sev }) {
                newPageIfNeeded(120)
                text("\(f.sev.rawValue.uppercased()) · CVSS \(f.cvss) · ATT&CK \(f.attack)",
                     font: .systemFont(ofSize: 9, weight: .semibold), color: UIColor(hex: 0xEE0000))
                text(f.title, font: .systemFont(ofSize: 15, weight: .bold), color: .black)
                text("target: \(f.target)", font: .systemFont(ofSize: 10), color: .darkGray)
                text("Evidence: \(f.evidence.prefix(600))", font: .systemFont(ofSize: 10), color: .black)
                text("Repro: \(f.repro.joined(separator: " — "))", font: .systemFont(ofSize: 10), color: .darkGray)
                text("Remediation: \(f.remediation)", font: .systemFont(ofSize: 10), color: .black)
            }
        }
        lastPDF = url
        return url
    }
}

extension UIColor {
    convenience init(hex: UInt32) {
        self.init(red: CGFloat((hex >> 16) & 0xff) / 255,
                  green: CGFloat((hex >> 8) & 0xff) / 255,
                  blue: CGFloat(hex & 0xff) / 255, alpha: 1)
    }
}
