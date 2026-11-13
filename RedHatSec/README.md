# RedHat Sec — IoT Attack Orchestrator (iOS 16.1.1, jailbroken)

Orchestratore offensivo per assessment su dispositivi IoT. Scan → Enumerate → Match vectors → Execute → Report (CVSS). Journal append-only (`Documents/audit_journal.txt`).

## Categorie coperte
Wi-Fi (deauth, PMKID, KRACK, FragAttacks, Dragonblood, MacSteaker, WPS, evil twin...), BLE/BT Classic (BlueBorne, BleedingTooth, BIAS, KNOB, Sweyntooth, BlueSmack, GATT enum/write...), NFC/RFID (Mifare Crypto1, DESFire CoPP, relay, cloni...), Zigbee (rejoin, touchlink, replay...), Z-Wave, LoRaWAN, Thread/Matter, Net/IP (Mirai telnet table, MQTT open broker, CoAP, UPnP, Modbus, RTSP...), Sub-GHz RF (RollJam, KeeLoq...), IR.

## Struttura
```
Sources/Core/  Theme, Models, VectorDB (catalogo), ShellRunner, Scanners, Orchestrator, ReportBuilder
Sources/UI/    Dashboard (radar), Catalog, Target, Report, App entry
```

## Build (macOS, Xcode 15+)
```bash
brew install xcodegen
cd RedHatSec && xcodegen
# build unsigned (TrollStore firma tutto):
xcodebuild -project RedHatSec.xcodeproj -scheme RedHatSec -configuration Release \
  -sdk iphoneos -derivedDataPath build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED="NO" CODE_SIGNING_ALLOWED="NO" build
# fake-sign con entitlements NFC:
ldid -SRedHatSec.entitlements build/Build/Products/Release-iphoneos/RedHatSec.app/RedHatSec
```

## Deploy su 16.1.1
- TrollStore: AirDrop/Files → condividi `.app` → install. Oppure `trollstore install <app>`.
- Alternativa: Filza install, o scp + `uicache` da shell JB.

## Capability matrix (on-device)
- **NATIVE**: BLE GATT enum/write/flood, TCP probes (MQTT/CoAP/Modbus/RTSP/SNMP/Telnet), mDNS/SSDP discovery, NFC Mifare read (entitlement).
- **SHELL TOOL**: delega a binari JB se presenti (`/var/jb/usr/bin` o `/usr/bin`): `nmap`, `tcpdump`, `aircrack-ng` suite, `hostapd`, `mdk3`, `reaver`, `killerbee`. Il tool li prova automaticamente; se assenti → vector marcato PLAN e finisce nel report come piano d'attacco.
- **PLAN**: exploit che richiedono radio/SDR esterni (RollJam, relay NFC, BlueBorne fw-level). Comparlono nel report con riproduzione completa.

Scope: usarlo solo su reti/lab in cui hai autorizzazione scritta. Tu decidi lo scope, io eseguo.
