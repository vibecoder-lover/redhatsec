import Foundation
import Network

// sessione rootd PERSISTENTE: una TCP a 127.0.0.1:4444 = una sh root viva (launchd inetd).
// cwd/env/export persistono tra i comandi, output streaming live, niente reconnect per comando.
final class RootdSession: ObservableObject {
    static let shared = RootdSession()

    @Published private(set) var connected = false
    @Published private(set) var busy = false

    var onChunk: ((String) -> Void)?            // output streaming (main)
    var onDone: ((Int32, String) -> Void)?      // marker trovato: (exit reale, cmd) (main)
    var onFail: ((String, String) -> Void)?     // rootd giu: (msg, cmd) (main)

    private var conn: NWConnection?
    private var ready = false
    private var outBuf = ""                     // comandi inviati prima che la conn sia ready
    private var inBuf: [UInt8] = []
    private var pending = 0
    private var lastCmd = ""
    private let q = DispatchQueue(label: "rhs.rootd.session")
    private let marker: [UInt8]

    private init() {
        let mk = "RHS_RC_" + UUID().uuidString.prefix(6).uppercased()
        marker = Array(("__" + mk + "_").utf8)
    }

    func send(_ line: String) {
        let cmd = "RHSROOT:{ \(line) ; }; echo \(String(decoding: marker, as: UTF8.self))$?\n"
        q.async {
            self.lastCmd = line
            if self.ready, let c = self.conn {
                self.pending += 1
                self.syncBusy()
                c.send(content: Data(cmd.utf8), completion: .contentProcessed { _ in })
            } else {
                self.outBuf += cmd
                self.connect()
            }
        }
    }

    func close() {
        q.async {
            self.ready = false
            self.conn?.cancel()
            self.conn = nil
            DispatchQueue.main.async { self.connected = false }
        }
    }

    private func connect() {
        guard conn == nil else { return }
        let c = NWConnection(host: "127.0.0.1", port: 4444, using: .tcp)
        conn = c
        c.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.q.async { self.onState(state) }
        }
        c.start(queue: q)
    }

    private func onState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            ready = true
            DispatchQueue.main.async { self.connected = true }
            flushOut()
            recv()
        case .failed(let e):
            drop("rootd: connessione fallita (\(e)) — jailbreak attivo? rhs-sudoers v1.1 installato?")
        case .cancelled:
            ready = false
            conn = nil
            DispatchQueue.main.async { self.connected = false }
        default:
            break
        }
    }

    private func flushOut() {
        guard !outBuf.isEmpty else { return }
        let b = outBuf
        outBuf = ""
        guard let c = conn else { return }
        pending += b.split(separator: "\n", omittingEmptySubsequences: false).count
        syncBusy()
        c.send(content: Data(b.utf8), completion: .contentProcessed { _ in })
    }

    private func drop(_ msg: String) {
        ready = false
        conn?.cancel()
        conn = nil
        let cmd = lastCmd
        if !inBuf.isEmpty {
            let txt = String(decoding: inBuf, as: UTF8.self)
            inBuf.removeAll()
            if !txt.isEmpty { DispatchQueue.main.async { self.onChunk?(txt) } }
        }
        pending = 0
        DispatchQueue.main.async {
            self.connected = false
            self.busy = false
        }
        lastCmd = ""
        if !cmd.isEmpty {
            DispatchQueue.main.async { self.onFail?(msg, cmd) }
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
        if isEOF { drop("rootd: stream chiuso dal lato server"); return }
        if let err { drop("rootd: recv err (\(err)) — reinstalla rhs-sudoers v1.1"); return }
        recv()
    }

    private func parseMarkers() {
        while true {
            guard let mi = indexOf(marker, in: inBuf) else { break }
            var end = mi + marker.count
            var digits = ""
            while end < inBuf.count, inBuf[end] >= 48, inBuf[end] <= 57 {
                digits.append(Character(UnicodeScalar(inBuf[end])))
                end += 1
            }
            if end < inBuf.count, inBuf[end] == 10 { end += 1 }
            let head = String(decoding: inBuf[0..<mi], as: UTF8.self)
            inBuf.removeFirst(end)
            let cmd = lastCmd
            if !head.isEmpty, let cb = onChunk {
                DispatchQueue.main.async { cb(head) }
            }
            if let e = Int32(digits) {
                pending = max(0, pending - 1)
                syncBusy()
                DispatchQueue.main.async { self.onDone?(e, cmd) }
            }
        }
        emitPartial()
    }

    // streaming live: emetti tutto tranne una coda che potrebbe contenere un marker spezzato
    private func emitPartial() {
        let hold = marker.count - 1
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
        let b = pending > 0
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
