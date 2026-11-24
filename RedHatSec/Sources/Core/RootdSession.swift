import Foundation
import Network

// rootd ONE-SHOT: ogni connessione esegue UNA riga (RHSROOT:{...}) e chiude.
// Pump: coda FIFO di comandi, 1 connessione per comando, riciclo dopo il marker,
// cwd/env persistono app-side e vengono re-inietti nel wrapper di ogni comando.
final class RootdSession: ObservableObject {
    static let shared = RootdSession()

    @Published private(set) var connected = false
    @Published private(set) var busy = false

    var onChunk: ((String) -> Void)?            // output streaming (main)
    var onDone: ((Int32, String) -> Void)?      // (exit reale, cmd) (main)
    var onFail: ((String, String) -> Void)?     // (msg, cmd) (main)

    private var conn: NWConnection?
    private var ready = false
    private var inBuf: [UInt8] = []
    private var queue: [String] = []            // comandi in attesa (FIFO)
    private var current = ""                    // comando in volo (1 connessione)
    private var consumed = false                // conn già servita (one-shot): in attesa di CWD+EOF
    private var tries = 0
    private var watchdog: DispatchWorkItem?
    private static let cmdTimeout: TimeInterval = 1800
    private var cwd = "/"
    private var envLines: [String]
    private let q = DispatchQueue(label: "rhs.rootd.session")
    private let marker: [UInt8]
    private static let cwdMark = "__RHSCWD_"
    private static let envKey = "rhs.env"

    private init() {
        let mk = "RHS_RC_" + UUID().uuidString.prefix(6).uppercased()
        marker = Array(("__" + mk + "_").utf8)
        envLines = UserDefaults.standard.stringArray(forKey: Self.envKey) ?? []
    }

    // pre-connect per il pallino verde: rootd spawn la sh che resta in attesa
    func warm() {
        q.async {
            if self.conn == nil, !self.ready { self.connect() }
        }
    }

    func close() {
        q.async {
            self.queue.removeAll()
            self.current = ""
            self.recycle()
            DispatchQueue.main.async {
                self.connected = false
                self.busy = false
            }
        }
    }

    func send(_ line: String) {
        let t = line
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespaces)
        q.async {
            self.trackEnv(t)
            self.queue.append(t)
            self.pump()
        }
    }

    // input RAW verso lo stdin del comando in volo (ESC/TAB/frecce/^D/^Z per i processi
    // interattivi). Il socket è già lo stdin della sh rootd: niente linea, niente nuova riga.
    func sendRaw(_ bytes: [UInt8]) {
        q.async {
            guard !bytes.isEmpty, !self.current.isEmpty, self.ready, !self.consumed,
                  let c = self.conn else { return }
            c.send(content: Data(bytes), completion: .contentProcessed { _ in })
        }
    }

    // ^C / ^\: il comando in volo è figlio della sh tracciata in /tmp/rhs.curpid.
    // rootd è inetd → una connessione separata può ucciderlo mentre la sessione
    // principale resta bloccata in attesa del marker. hard = SIGKILL diretto.
    func interrupt(hard: Bool = false) {
        q.async {
            guard !self.current.isEmpty else { return }
            self.queue.removeAll()
            self.current = ""
            self.recycle()
            DispatchQueue.main.async {
                self.connected = false
                self.busy = false
            }
            self.pump()
            let sig = hard ? "KILL" : "TERM"
            let script = "p=$(cat /tmp/rhs.curpid 2>/dev/null); if [ -n \"$p\" ]; then "
                + "for k in $(ps -A -o pid=,ppid= 2>/dev/null | awk -v P=\"$p\" '$2==P{print $1}'); do kill -\(sig) $k 2>/dev/null; done; "
                + "kill -\(sig) $p 2>/dev/null; sleep 1; "
                + "for k in $(ps -A -o pid=,ppid= 2>/dev/null | awk -v P=\"$p\" '$2==P{print $1}'); do kill -KILL $k 2>/dev/null; done; "
                + "kill -KILL $p 2>/dev/null; fi; rm -f /tmp/rhs.curpid; echo RHS-INT"
            DispatchQueue.global(qos: .userInitiated).async {
                _ = RootdClient.exec(script, timeout: 8)
            }
        }
    }

    // MARK: pump one-shot

    private func pump() {
        // !consumed: la conn one-shot ha già stampato il marker → è drenata, il prossimo
        // comando deve attendere silentClose (prima veniva legato alla conn vecchia e
        // finiva in lost() come falso errore di rete)
        guard current.isEmpty, !consumed, !queue.isEmpty else { syncBusy(); return }
        current = queue.removeFirst()
        tries = 0
        syncBusy()
        if ready, let c = conn, !consumed {
            fire(current, on: c)
        } else if conn == nil {
            connect()   // on ready → fire(current)
        }
        // conn consumata ma ancora aperta: il fire avviene dopo silentClose → pump
    }

    private func fire(_ t: String, on c: NWConnection) {
        startWatchdog()
        c.send(content: Data(wrapper(t).utf8), completion: .contentProcessed { _ in })
    }

    // watchdog: se il marker non arriva mai (sh bloccata da un comando che ignora TERM,
    // rootd che non risponde) la coda non deve restare appesa per sempre
    private func startWatchdog() {
        watchdog?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.q.async {
                guard !self.current.isEmpty else { return }
                self.lost("rootd: nessun marker entro \(Int(Self.cmdTimeout))s")
            }
        }
        watchdog = w
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.cmdTimeout, execute: w)
    }

    private func stopWatchdog() {
        watchdog?.cancel()
        watchdog = nil
    }

    private func wrapper(_ t: String) -> String {
        var pre = ""
        // il sh di launchd parte senza /var/jb nel PATH: senza questo ogni tool root
        // rispondeva 127 (command not found) e scattava l'auto-install a vuoto
        pre += "export PATH=/var/jb/usr/local/bin:/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH; "
        pre += "export LD_LIBRARY_PATH=/var/jb/usr/lib:$LD_LIBRARY_PATH; "
        // pid della sh corrente: serve a ^C (kill del comando in volo da un'altra conn rootd)
        pre += "echo $$ > /tmp/rhs.curpid; "
        let cq = cwd.replacingOccurrences(of: "'", with: "'\\''")
        pre += "cd '\(cq)' 2>/dev/null; "
        for l in envLines { pre += l.replacingOccurrences(of: "\n", with: " ") + "; " }
        let mk = String(decoding: marker, as: UTF8.self)
        return "RHSROOT:{ \(pre)\(t) ; __rhs_rc=$?; echo \"\(mk)$__rhs_rc\"; echo \"\(Self.cwdMark)$PWD\"; }\n"
    }

    private func trackEnv(_ t: String) {
        guard t.hasPrefix("export ") || t.hasPrefix("unset ") else { return }
        func keyOf(_ line: String) -> String {
            let b = line.hasPrefix("export ") ? line.dropFirst(7) : line.dropFirst(6)
            return b.split(separator: "=", maxSplits: 1).first
                .map { String($0).trimmingCharacters(in: .whitespaces) } ?? ""
        }
        let key = keyOf(t)
        guard !key.isEmpty else { return }
        // stessa variabile ri-esportata: sostituisci invece di accumulare per sempre
        envLines.removeAll { keyOf($0) == key }
        envLines.append(t)
        if envLines.count > 64 { envLines.removeFirst(envLines.count - 64) }
        UserDefaults.standard.set(envLines, forKey: Self.envKey)
    }

    // il conn è consumato dopo un marker (one-shot) → chiudi e passa al prossimo
    private func recycle() {
        stopWatchdog()
        ready = false
        conn?.cancel()
        conn = nil
        consumed = false
        inBuf.removeAll()
    }

    // MARK: connessione

    private func connect() {
        guard conn == nil else { return }
        let c = NWConnection(host: "127.0.0.1", port: 4444, using: .tcp)
        conn = c
        // identità della connessione catturata: un .cancelled/.failed tardivo della
        // connessione vecchia non deve toccare quella nuova (prima: conn! crash / stato falso)
        c.stateUpdateHandler = { [weak self, weak c] state in
            guard let self else { return }
            self.q.async { self.onState(state, from: c) }
        }
        c.start(queue: q)
    }

    private func onState(_ state: NWConnection.State, from src: NWConnection?) {
        guard let src, src === conn else { return }
        switch state {
        case .ready:
            ready = true
            DispatchQueue.main.async { self.connected = true }
            if !current.isEmpty {
                fire(current, on: src)
            }
            recv()
        case .failed(let e):
            lost("rootd: connessione fallita (\(e)) — jailbreak attivo? rhs-sudoers v1.1 installato?")
        case .cancelled:
            ready = false
            conn = nil
            consumed = false
            DispatchQueue.main.async { self.connected = false }
        default:
            break
        }
    }

    private func recv() {
        guard let c = conn else { return }
        c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isEOF, err in
            guard let self else { return }
            self.q.async { self.onRecv(data: data, isEOF: isEOF, err: err) }
        }
    }

    private func onRecv(data: Data?, isEOF: Bool, err: NWError?) {
        if let data, !data.isEmpty {
            inBuf += Array(data)
            parseMarkers()
        }
        if isEOF {
            // marker già preso → chiusura normale; altrimenti il comando si è perso: retry
            if current.isEmpty {
                silentClose()
            } else {
                lost("rootd: stream chiuso a comando incompleto")
            }
            return
        }
        if let err {
            if current.isEmpty { silentClose() }
            else { lost("rootd: recv err (\(err)) — reinstalla rhs-sudoers v1.1") }
            return
        }
        recv()
    }

    // comando perso (conn chiusa senza marker): max 2 tentativi poi fallback
    private func lost(_ msg: String) {
        tries += 1
        if tries >= 2 {
            let cmd = current
            current = ""
            recycle()
            DispatchQueue.main.async {
                self.connected = false
                self.busy = false
            }
            if !cmd.isEmpty {
                DispatchQueue.main.async { self.onFail?(msg, cmd) }
            }
            pump()
        } else {
            recycle()
            DispatchQueue.main.async { self.connected = false }
            connect()   // on ready → fire(current) di nuovo
        }
    }
    private func silentClose() {
        ready = false
        conn?.cancel()
        conn = nil
        if !inBuf.isEmpty {
            let txt = String(decoding: inBuf, as: UTF8.self)
            inBuf.removeAll()
            if !txt.isEmpty { DispatchQueue.main.async { self.onChunk?(txt) } }
        }
        consumed = false
        DispatchQueue.main.async { self.connected = false }
        pump()   // il conn consumato si è chiuso: si può sparare il prossimo
    }

    // MARK: parse

    private func parseMarkers() {
        let cwdB = Array(Self.cwdMark.utf8)
        while true {
            let iRC = indexOf(marker, in: inBuf)
            let iCWD = indexOf(cwdB, in: inBuf)
            if iRC == nil && iCWD == nil { break }
            if let a = iRC, (iCWD == nil || a < iCWD!) {
                takeRC(at: a)
            } else if let b = iCWD {
                takeCWD(at: b)
            }
        }
        emitPartial()
    }

    private func takeRC(at mi: Int) {
        var end = mi + marker.count
        var digits = ""
        while end < inBuf.count, inBuf[end] >= 48, inBuf[end] <= 57 {
            digits.append(Character(UnicodeScalar(inBuf[end])))
            end += 1
        }
        if end < inBuf.count, inBuf[end] == 10 { end += 1 }
        let head = String(decoding: inBuf[0..<mi], as: UTF8.self)
        inBuf.removeFirst(end)
        let cmd = current
        if !head.isEmpty, let cb = onChunk {
            DispatchQueue.main.async { cb(head) }
        }
        if let e = Int32(digits) {
            current = ""
            consumed = true
            stopWatchdog()
            syncBusy()
            DispatchQueue.main.async { self.onDone?(e, cmd) }
            // il conn rimane aperto fino a CWD+EOF (one-shot): lì silentClose → pump
            pump()
        }
    }

    private func takeCWD(at mi: Int) {
        var end = mi + Self.cwdMark.utf8.count
        var bytes: [UInt8] = []
        while end < inBuf.count, inBuf[end] != 10 {
            bytes.append(inBuf[end])
            end += 1
        }
        if end < inBuf.count, inBuf[end] == 10 { end += 1 }
        inBuf.removeFirst(end)
        let path = String(decoding: bytes, as: UTF8.self)
        if !path.isEmpty { cwd = path }
    }

    // streaming live: emetti tutto tranne una coda che potrebbe contenere un marker spezzato
    private func emitPartial() {
        let hold = max(marker.count, Self.cwdMark.utf8.count + 1) - 1
        guard inBuf.count > hold else { return }
        let cut = inBuf.count - hold
        let slice = Array(inBuf[0..<cut])
        let (txt, keep) = utf8Split(slice)
        let emitCount = cut - keep
        guard emitCount > 0 else { return }
        inBuf.removeFirst(emitCount)
        if !txt.isEmpty, let cb = onChunk {
            DispatchQueue.main.async { cb(txt) }
        }
    }

    private func syncBusy() {
        let b = !current.isEmpty || !queue.isEmpty
        DispatchQueue.main.async { self.busy = b }
    }

    private func indexOf(_ needle: [UInt8], in hay: [UInt8]) -> Int? {
        guard hay.count >= needle.count, !needle.isEmpty else { return nil }
        let first = needle[0]
        let lim = hay.count - needle.count
        var i = 0
        while i <= lim {
            if hay[i] == first {
                var j = 1
                while j < needle.count, hay[i + j] == needle[j] { j += 1 }
                if j == needle.count { return i }
            }
            i += 1
        }
        return nil
    }

    // tiene indietro un carattere UTF-8 spezzato tra due chunk (restano in inBuf)
    private func utf8Split(_ b: [UInt8]) -> (String, Int) {
        guard let last = b.last else { return ("", 0) }
        var hold = 0
        if last >= 0xC0 {
            hold = last >= 0xF0 ? 4 : (last >= 0xE0 ? 3 : 2)
        } else if last >= 0x80 {
            var i = b.count - 1
            var cont = 0
            while i >= 0, b[i] >= 0x80, b[i] < 0xC0 { cont += 1; i -= 1 }
            if i >= 0 {
                let lead = b[i]
                let need = lead >= 0xF0 ? 4 : (lead >= 0xE0 ? 3 : 2)
                if cont + 1 < need { hold = need - cont }
            }
        }
        guard hold < b.count else { return ("", b.count) }
        let txt = String(decoding: b[0..<(b.count - hold)], as: UTF8.self)
        return (txt, hold)
    }
}
