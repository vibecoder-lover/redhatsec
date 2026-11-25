import Foundation
import CoreBluetooth

// Periferica BLE di test lato iPhone: serve come target reale per
// conn flood / SMP / ATT fuzz del bridge ESP32 (Fase B) senza hardware extra.
final class BLEAdvertiser: NSObject, ObservableObject, CBPeripheralManagerDelegate {
    @Published private(set) var advertising = false
    @Published private(set) var btState = "off"
    @Published private(set) var peers = 0
    @Published private(set) var msg = ""

    private var pm: CBPeripheralManager?
    private var svc: CBMutableService?
    private var wantOn = false
    private let svcUUID = CBUUID(string: "0000FFF0-0000-1000-8000-00805F9B34FB")
    private let chrUUID = CBUUID(string: "0000FFF1-0000-1000-8000-00805F9B34FB")
    private var chrValue = Data("RHS".utf8)

    func toggle() {
        if advertising { stop() } else { start() }
    }

    func start() {
        wantOn = true
        if pm == nil {
            pm = CBPeripheralManager(delegate: self, queue: nil)
            btState = "init"
            return
        }
        guard pm?.state == .poweredOn else {
            btState = stateName(pm?.state)
            msg = "Bluetooth non pronto: \(btState)"
            return
        }
        begin()
    }

    func stop() {
        wantOn = false
        pm?.stopAdvertising()
        pm?.removeAllServices()
        svc = nil
        advertising = false
        btState = "off"
        peers = 0
        msg = ""
    }

    private func begin() {
        if svc == nil {
            let c = CBMutableCharacteristic(type: chrUUID, properties: [.read, .write, .writeWithoutResponse, .notify],
                                            value: nil, permissions: [.readable, .writeable])
            let s = CBMutableService(type: svcUUID, primary: true)
            s.characteristics = [c]
            svc = s
            pm?.add(s)
            return
        }
        pm?.startAdvertising([
            CBAdvertisementDataLocalNameKey: "RHS-Test",
            CBAdvertisementDataServiceUUIDsKey: [svcUUID]
        ])
        advertising = true
        btState = "advertising"
        msg = "RHS-Test · FFF0/FFF1"
    }

    private func stateName(_ s: CBManagerState?) -> String {
        switch s {
        case .poweredOn: return "on"
        case .poweredOff: return "off"
        case .unauthorized: return "unauthorized"
        case .unsupported: return "unsupported"
        case .resetting: return "resetting"
        default: return "unknown"
        }
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        DispatchQueue.main.async {
            self.btState = self.stateName(peripheral.state)
            if peripheral.state == .poweredOn && self.wantOn && !self.advertising {
                self.begin()
            } else if peripheral.state != .poweredOn && self.wantOn {
                self.advertising = false
                self.msg = "Bluetooth \(self.btState)"
            }
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        DispatchQueue.main.async {
            if let e = error {
                self.msg = "add service: \(e.localizedDescription)"
                return
            }
            if self.wantOn { self.begin() }
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        DispatchQueue.main.async {
            if let e = error {
                self.advertising = false
                self.msg = "adv: \(e.localizedDescription)"
            } else {
                self.advertising = true
            }
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        DispatchQueue.main.async {
            self.peers += 1
            self.msg = "central \(central.identifier.uuidString.prefix(8)) connesso"
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        DispatchQueue.main.async {
            self.peers = max(0, self.peers - 1)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for r in requests {
            if let v = r.value { chrValue = v }
            peripheral.respond(to: r, withResult: .success)
        }
        DispatchQueue.main.async {
            self.msg = "write \(requests.map { $0.value?.count ?? 0 }.reduce(0, +))B da \(requests.first?.central.identifier.uuidString.prefix(8) ?? "-")"
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        request.value = chrValue
        peripheral.respond(to: request, withResult: .success)
    }
}
