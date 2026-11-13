import Foundation

enum TargetNamer {
    static func pretty(_ t: TargetDevice, rawName: String) -> String {
        let raw = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        if looksGood(raw) { return raw }
        switch t.proto {
        case .ble:
            if let v = t.vendor {
                return "\(v) \(kindFromServices(t.services))"
            }
            if !t.services.isEmpty {
                return kindFromServices(t.services) + " (BLE)"
            }
            let sig = t.mac?.prefix(4).description ?? "??"
            return "BLE Device \(sig)"
        case .wifi:
            if let b = t.mac, !b.isEmpty, b != "?" {
                return "Wi-Fi Net (\(b.suffix(5)))"
            }
            return "Wi-Fi Network"
        case .net:
            if let d = t.extra["desc"], let friendly = friendlyFromSSDP(d) {
                return friendly
            }
            if let host = t.extra["host"] {
                return "Host \(tailIP(host))"
            }
            return "LAN Device"
        case .nfc:
            if let rawd = t.extra["raw"], rawd.contains("MIFARE") {
                return "NFC \(rawd.split(separator: " ").dropFirst().first.map(String.init) ?? "Tag")"
            }
            return "NFC Tag"
        case .classic:
            return "BT Classic Device"
        case .zigbee, .zwave, .lora, .thread:
            return "\(t.proto.rawValue) Node"
        case .rfid:
            return "RFID Badge"
        case .rf:
            return "Sub-GHz Source"
        case .ir:
            return "IR Emitter"
        }
    }

    private static func looksGood(_ s: String) -> Bool {
        guard !s.isEmpty, s.count >= 3 else { return false }
        let uuidish = s.range(of: "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}", options: .regularExpression) != nil
        let ssdpish = s.hasPrefix("SSDP http")
        let dotish = s.hasPrefix(".") || s.hasSuffix(".")
        return !uuidish && !ssdpish && !dotish
    }

    static func kindFromServices(_ services: [String]) -> String {
        let joined = services.joined(separator: " ")
        if joined.contains("Heart Rate") { return "Fitness Sensor" }
        if joined.contains("Battery") { return "Tracked Device" }
        if joined.contains("Thermometer") { return "Health Sensor" }
        if joined.contains("Matter") { return "Smart Home Node" }
        if joined.contains("Fast Pair") { return "Quick Pair Gadget" }
        if joined.contains("Vendor SVC") { return "Vendor Peripheral" }
        if joined.contains("Device Information") { return "BLE Info Peripheral" }
        if joined.contains("User Data") { return "Wearable" }
        return "BLE Peripheral"
    }

    static func friendlyFromSSDP(_ desc: String) -> String? {
        guard let data = try? String(contentsOf: URL(string: desc)!, encoding: .utf8) else { return nil }
        if let r = data.range(of: "<friendlyName>(.*?)</friendlyName>", options: .regularExpression) {
            let name = String(data[r])
                .replacingOccurrences(of: "<friendlyName>", with: "")
                .replacingOccurrences(of: "</friendlyName>", with: "")
            if !name.isEmpty { return name }
        }
        if let r = data.range(of: "<modelDescription>(.*?)</modelDescription>", options: .regularExpression) {
            let name = String(data[r])
                .replacingOccurrences(of: "<modelDescription>", with: "")
                .replacingOccurrences(of: "</modelDescription>", with: "")
            if !name.isEmpty { return name }
        }
        return nil
    }

    static func tailIP(_ host: String) -> String {
        let parts = host.split(separator: ".")
        if parts.count >= 2 {
            return ".\(parts[parts.count - 2]).\(parts[parts.count - 1])"
        }
        return host
    }

    static func hintFromBanner(_ banners: String) -> String? {
        if banners.contains("MQTT") { return "MQTT Broker" }
        if banners.contains("HTTP") { return "HTTP Service" }
        if banners.contains("Modbus") || banners.contains("modbus") { return "PLC/Modbus" }
        if banners.contains("RTSP") { return "IP Camera" }
        if banners.contains("SSH") { return "SSH Host" }
        if banners.contains("coap") { return "CoAP Node" }
        return nil
    }
}
