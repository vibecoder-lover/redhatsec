import Foundation

// Fase A — export pcap (DLT 127 + radiotap 8B) delle catture EAPOL dell'ESP32.
// aircrack-ng/hcxtools leggono il file così com'è; nessuna dipendenza esterna.
enum WifiCapture {
    static func pcap(_ caps: [BridgeManager.Handshake]) -> Data {
        var d = Data()
        func le16(_ v: UInt16) { d.append(UInt8(v & 0xFF)); d.append(UInt8(v >> 8)) }
        func le32(_ v: UInt32) { le16(UInt16(v & 0xFFFF)); le16(UInt16(v >> 16)) }

        le16(0xA1B2)  // magic 0xA1B2C3D4 (little endian)
        le16(0xC3D4)
        le16(2); le16(4)              // version 2.4
        le32(0); le32(0)              // thiszone, sigfigs
        le32(65535)                   // snaplen
        le32(127)                     // LINKTYPE_IEEE802_11_RADIOTAP

        var sec = UInt32(Date().timeIntervalSince1970)
        var usec: UInt32 = 0
        let rt: [UInt8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]
        for h in caps {
            for m in h.frames {
                let pkt = Data(rt) + m.frame
                le32(sec)
                le32(usec)
                le32(UInt32(pkt.count))
                le32(UInt32(pkt.count))
                d.append(pkt)
                usec &+= 100
                if usec >= 1_000_000 { usec = 0; sec &+= 1 }
            }
        }
        return d
    }

    static func write(_ caps: [BridgeManager.Handshake]) -> URL? {
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return nil }
        let dir = docs.appendingPathComponent("RedHatSec/captures", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        let url = dir.appendingPathComponent("capture-\(f.string(from: Date())).pcap")
        do {
            try pcap(caps).write(to: url)
            return url
        } catch {
            return nil
        }
    }
}
