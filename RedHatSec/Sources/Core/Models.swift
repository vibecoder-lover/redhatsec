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
