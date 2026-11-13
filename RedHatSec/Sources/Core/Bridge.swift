import Foundation
import CoreBluetooth

// Bridge radio remota (ESP32/ESP8266) via BLE — sblocca i vettori PLAN
// (deauth, beacon spam, PMKID) senza uscire dall'app.
// Protocollo binario framed (stile NRSuite/Marauder, non ASCII):
//   TX: [0xA5][len:u16 LE][seq:u8][cmd:u8][payload][crc8]
//   RX: [0x5A][len:u16 LE][seq:u8(=cmd di richiesta)][status:u8][payload][crc8]
final class BridgeManager: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    // HM-10/ESP32 classico: FFE0 (service) / FFE1 (write+notify)
    static let svcUUID = CBUUID(string: "0000FFE0-0000-1000-8000-00805F9B34FB")
    static let chrUUID = CBUUID(string: "0000FFE1-0000-1000-8000-00805F9B34FB")

    @Published var state = "off"
    @Published var connected = false
    @Published var deviceName: String?
    @Published var bridgeLog: [String] = []
    @Published var scanNets: [BridgeNet] = []

    struct BridgeNet: Identifiable {
        var id: String { bssid }
        let bssid: String
        let ssid: String
        let ch: Int
        let rssi: Int
        let sec: String
    }

    enum Cmd: UInt8 {
        case ping = 0x01
        case wifiScan = 0x02
        case wifiResults = 0x03
        case deauth = 0x04
        case beaconSpam = 0x05
        case pmkid = 0x06
        case stop = 0x07
    }

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var chr: CBCharacteristic?
    private var seq: UInt8 = 0
    private var rxBuffer: [UInt8] = []
    private var responseCont: CheckedContinuation<(UInt8, Data)?, Never>?
    private var scanCont: CheckedContinuation<[BridgeNet], Never>?

    func start() {
        guard central == nil else { return }
        state = "scanning"
        central = CBCentralManager(delegate: self, queue: nil)
    }

    func log(_ s: String) {
        bridgeLog.append("[bridge] \(s)")
        if bridgeLog.count > 200 { bridgeLog.removeFirst(bridgeLog.count - 200) }
    }

    // MARK: CBCentral

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            central.scanForPeripherals(withServices: [Self.svcUUID], options: nil)
            state = "ricerca ESP32…"
        } else {
            state = "BLE off"
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
        deviceName = peripheral.name ?? "ESP32"
        state = "connessione a \(deviceName ?? "?")…"
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([Self.svcUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        state = "connessione fallita"
        log("connect fail: \(error?.localizedDescription ?? "?")")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let svc = peripheral.services?.first(where: { $0.uuid == Self.svcUUID }) else { return }
        peripheral.discoverCharacteristics([Self.chrUUID], for: svc)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let c = service.characteristics?.first(where: { $0.uuid == Self.chrUUID }) else { return }
        chr = c
        peripheral.setNotifyValue(true, for: c)
        connected = true
        state = "connesso (\(deviceName ?? "ESP32"))"
        log("bridge connesso ✓")
        send(.ping)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        connected = false
        chr = nil
        state = "disconnesso"
        log("bridge disconnesso")
    }

    // MARK: Framing

    private func crc8(_ data: [UInt8]) -> UInt8 {
        var crc: UInt8 = 0
        for b in data {
            crc ^= b
            for _ in 0..<8 {
                crc = (crc & 0x80) != 0 ? (crc << 1) ^ 0x07 : (crc << 1)
            }
        }
        return crc
    }

    private func send(_ cmd: Cmd, payload: [UInt8] = []) {
        guard connected, let chr else {
            log("send \(cmd): bridge non connesso")
            return
        }
        seq &+= 1
        var frame: [UInt8] = [0xA5, 0, 0, seq, cmd.rawValue]
        frame[1] = UInt8(payload.count & 0xFF)
        frame[2] = UInt8((payload.count >> 8) & 0xFF)
        frame += payload
        frame.append(crc8(frame))
        peripheral?.writeValue(Data(frame), for: chr, type: .withResponse)
        log("TX \(cmd) (\(payload.count)B)")
    }

    private func sendAwait(_ cmd: Cmd, payload: [UInt8] = [], timeout: TimeInterval = 8) async -> (UInt8, Data)? {
        guard connected else { return nil }
        return await withCheckedContinuation { c in
            responseCont = c
            send(cmd, payload: payload)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, self.responseCont != nil else { return }
                self.responseCont = nil
                c.resume(returning: nil)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let data = characteristic.value else { return }
        rxBuffer += [UInt8](data)
        guard let frame = popFrame() else { return }
        guard frame.status == 0x00 else {
            log("RX error \(frame.status)")
            responseCont?.resume(returning: (frame.status, Data()))
            responseCont = nil
            return
        }
        switch frame.cmdEcho {
        case Cmd.wifiResults.rawValue:
            let nets = parseNets(frame.payload)
            scanCont?.resume(returning: nets)
            scanCont = nil
            responseCont?.resume(returning: (0, Data()))
            responseCont = nil
        default:
            responseCont?.resume(returning: (0, frame.payload))
            responseCont = nil
        }
    }

    private func popFrame() -> (status: UInt8, cmdEcho: UInt8, payload: [UInt8])? {
        while rxBuffer.count >= 5 {
            guard rxBuffer[0] == 0x5A else { rxBuffer.removeFirst(); continue }
            let len = Int(rxBuffer[1]) | (Int(rxBuffer[2]) << 8)
            guard rxBuffer.count >= len + 6 else { return nil }
            let body = Array(rxBuffer[1..<(len + 5)])
            let crc = rxBuffer[5 + len]
            guard crc8(body) == crc else {
                log("crc err — scarto frame")
                rxBuffer.removeFirst(6 + len)
                continue
            }
            let seqb = rxBuffer[3]
            let status = rxBuffer[4]
            let payload = Array(rxBuffer[5..<(5 + len)])
            rxBuffer.removeFirst(6 + len)
            return (status, seqb, payload)
        }
        return nil
    }

    // payload nets: [rssi:i8][ch:u8][bssid:6][sec:u8][ssidLen:u8][ssid…]
    private func parseNets(_ p: [UInt8]) -> [BridgeNet] {
        var out: [BridgeNet] = []
        var i = 0
        while i + 10 <= p.count {
            let rssi = Int(Int8(bitPattern: p[i])); i += 1
            let ch = Int(p[i]); i += 1
            let bssid = p[i..<(i + 6)].map { String(format: "%02X", $0) }.joined(separator: ":"); i += 6
            let sec = p[i] == 0 ? "OPEN" : "WPA2"; i += 1
            let sl = Int(p[i]); i += 1
            guard i + sl <= p.count else { break }
            let ssid = String(decoding: p[i..<(i + sl)], as: UTF8.self); i += sl
            out.append(BridgeNet(bssid: bssid, ssid: ssid.isEmpty ? "(hidden)" : ssid, ch: ch, rssi: rssi, sec: sec))
        }
        return out
    }

    // MARK: API

    func ping() async -> Bool {
        let r = await sendAwait(.ping)
        return r != nil
    }

    func wifiScan(seconds: Int = 8) async -> [BridgeNet] {
        guard connected else { return [] }
        let nets = await withCheckedContinuation { (c: CheckedContinuation<[BridgeNet], Never>) in
            scanCont = c
            send(.wifiScan, payload: [UInt8(seconds)])
            DispatchQueue.global().asyncAfter(deadline: .now() + Double(seconds) + 6) { [weak self] in
                guard let self, self.scanCont != nil else { return }
                self.scanCont = nil
                c.resume(returning: [])
            }
        }
        scanNets = nets
        log("wifi scan: \(nets.count) rete(e)")
        return nets
    }

    func deauth(mac: String, ch: Int, count: Int = 10) async -> Bool {
        guard connected, var m = mac.replacingOccurrences(of: ":", with: "").hexBytes, m.count == 6 else {
            log("deauth: mac invalido")
            return false
        }
        m.append(UInt8(ch))
        m.append(UInt8(count))
        let r = await sendAwait(.deauth, payload: m)
        let ok = r?.0 == 0
        log(ok ? "deauth \(mac) inviata ✓" : "deauth fallita")
        return ok
    }

    func beaconSpam(ssids: [String]) async -> Bool {
        guard connected, !ssids.isEmpty else { return false }
        var payload: [UInt8] = [UInt8(ssids.count)]
        for s in ssids.prefix(16) {
            let b = Array(s.utf8.prefix(32))
            payload.append(UInt8(b.count))
            payload += b
        }
        let r = await sendAwait(.beaconSpam, payload: payload, timeout: 10)
        log(r?.0 == 0 ? "beacon spam attivo (\(ssids.count) SSID)" : "beacon spam fallito")
        return r?.0 == 0
    }

    func pmkid(mac: String, ch: Int) async -> Bool {
        guard connected, var m = mac.replacingOccurrences(of: ":", with: "").hexBytes, m.count == 6 else { return false }
        m.append(UInt8(ch))
        let r = await sendAwait(.pmkid, payload: m, timeout: 20)
        return r?.0 == 0
    }

    func stopAll() {
        send(.stop)
    }
}

extension String {
    var hexBytes: [UInt8]? {
        guard count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var it = makeIterator()
        while let a = it.next(), let b = it.next(),
              let x = UInt8(String(a), radix: 16), let y = UInt8(String(b), radix: 16) {
            out.append(x << 4 | y)
        }
        return out.count == count / 2 ? out : nil
    }
}
