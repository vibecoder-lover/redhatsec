import Foundation

enum Proto: String, CaseIterable, Codable, Identifiable {
    case wifi = "Wi-Fi"
    case ble = "BLE"
    case classic = "BT Classic"
    case nfc = "NFC"
    case rfid = "RFID"
    case zigbee = "Zigbee"
    case zwave = "Z-Wave"
    case lora = "LoRa"
    case thread = "Thread"
    case net = "Net/IP"
    case rf = "Sub-GHz"
    case ir = "IR"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .wifi: return "wifi"
        case .ble, .classic: return "dot.radiowaves.left.and.right"
        case .nfc, .rfid: return "wave.3.right"
        case .zigbee, .zwave, .lora, .thread: return "antenna.radiowaves.left.and.right"
        case .net: return "network"
        case .rf: return "dot.radiowaves.right"
        case .ir: return "light.beacon.max"
        }
    }
}

enum Capability: Codable, Equatable {
    case native            // eseguibile on-device con API pubbliche
    case shellTool(String) // richiede binario JB, es. "nmap"
    case plan              // richiede radio/SDR esterno → va in report come piano
}

struct AttackVector: Identifiable, Codable {
    let id: String
    let name: String
    let proto: Proto
    let year: Int
    let ref: String
    let attack: String      // MITRE ATT&CK technique
    let cvss: Double
    let cvssVec: String
    let sev: Sev
    let prereq: String
    let brief: String
    let remediation: String
    let cap: Capability
    let hint: String
}

struct TargetDevice: Identifiable, Codable, Hashable {
    var id = UUID()
    var name: String
    var proto: Proto
    var rssi: Int
    var mac: String?
    var vendor: String?
    var services: [String] = []
    var via: String
    var extra: [String: String] = [:]
}

enum ProofType: String, Codable {
    case bannerOnly, responseConfirmed, exploitConfirmed
}

struct Finding: Identifiable, Codable {
    var id = UUID()
    var vectorID: String
    var title: String
    var target: String
    var sev: Sev
    var cvss: Double
    var cvssVec: String
    var attack: String
    var evidence: String
    var repro: [String]
    var impact: String
    var remediation: String
    var proof: ProofType = .bannerOnly
    var evidenceHash: String = ""
    var utc: String = ""
}

struct Report: Identifiable, Codable {
    var id = UUID()
    var title: String
    var date: Date
    var targets: [TargetDevice]
    var findings: [Finding]
}

struct LogEntry: Identifiable {
    let id = UUID()
    let t = Date()
    let level: Level
    let text: String
    enum Level: String { case info, warn, good, bad, exec }
}

struct AttackRecord: Identifiable, Codable {
    var id = UUID()
    var date = Date()
    var vectorID: String
    var vector: String
    var target: String
    var outcome: String
    var evidence: String
}

struct NFCDump: Identifiable, Codable {
    var id = UUID()
    var date = Date()
    var uid: String
    var family: String
    var pages: [String]
    var ndefHex: [String]
    var ndefText: [String]
    var kind: String

    var title: String { "\(kind) \(uid.prefix(10))" }

    init(uid: String, family: String, pages: [String], ndefHex: [String], ndefText: [String], kind: String) {
        self.uid = uid
        self.family = family
        self.pages = pages
        self.ndefHex = ndefHex
        self.ndefText = ndefText
        self.kind = kind
    }

    enum CodingKeys: String, CodingKey {
        case id, date, uid, family, pages, ndefHex, ndefText, kind
    }

    // decode tollerante: i dump scritti da una versione vecchia (senza id/date o
    // senza un array) non devono far fallire TUTTO il loadDumps
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = ((try? c.decodeIfPresent(UUID.self, forKey: .id)) ?? nil) ?? UUID()
        date = ((try? c.decodeIfPresent(Date.self, forKey: .date)) ?? nil) ?? Date()
        uid = ((try? c.decodeIfPresent(String.self, forKey: .uid)) ?? nil) ?? "?"
        family = ((try? c.decodeIfPresent(String.self, forKey: .family)) ?? nil) ?? "?"
        pages = ((try? c.decodeIfPresent([String].self, forKey: .pages)) ?? nil) ?? []
        ndefHex = ((try? c.decodeIfPresent([String].self, forKey: .ndefHex)) ?? nil) ?? []
        ndefText = ((try? c.decodeIfPresent([String].self, forKey: .ndefText)) ?? nil) ?? []
        kind = ((try? c.decodeIfPresent(String.self, forKey: .kind)) ?? nil) ?? "Tag"
    }
}

enum Phase: String, CaseIterable, Identifiable {
    case idle, scan, enumerate, match, armed, execute, report
    var id: String { rawValue }
    var label: String {
        switch self {
        case .idle: return "Idle"
        case .scan: return "Scan"
        case .enumerate: return "Enumerate"
        case .match: return "Match Vectors"
        case .armed: return "Armed"
        case .execute: return "Execute"
        case .report: return "Report"
        }
    }
}
