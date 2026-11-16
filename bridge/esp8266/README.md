# RHSBridge ESP8266

Firmware bridge radio per RedHatSec: monitor mode + frame injection su 2.4GHz,
servo TCP `:3333` con il protocollo framed dell'app (byte-exact, vedi
`RedHatSec/Sources/Core/Bridge.swift`).

## Flash

1. Arduino IDE (o PlatformIO) → board **Generic ESP8266 Module** / NodeMCU 1.0
2. Librerie: solo ESP8266 core (nessuna dipendenza extra)
3. Upload `RHSBridge/RHSBridge.ino` (80MHz, Flash 4MB, upload via USB/esptool)
4. Seriale 115200 → `[rhs] bridge up :3333`

## Collegamento dall'app

- **AP mode**: Impostazioni iOS → WiFi → `RHS-Bridge` (pass `rhsbridge`) →
  nell'app Bridge → connect manuale `192.168.4.1:3333`
- **STA mode** (stessa rete): cmd `joinTarget` dall'app → l'ESP entra nella rete
  target e pubblica mDNS `_rhsbridge._tcp`

## Comandi implementati

| Cmd | Funzione |
|---|---|
| 0x01 | ping |
| 0x02/0x03 | scan WiFi (async + results) |
| 0x04 | deauth burst (reason 7, DA broadcast, burst su canale target) |
| 0x05 | beacon spam round-robin (canale corrente, single-radio) |
| 0x06 | sniff EAPOL (PMKID/handshake check) ≤25s |
| 0x07 | stop |
| 0x08 | join rete target (AP resta attivo) |
| 0x10 | port scan con banner |
| 0x11/0x12 | roundtrip TCP/UDP verso host target |

Nota radio: l'ESP8266 ha una sola radio — durante burst/sniff l'AP si sposta
sul canale target (`softAP(ssid,pass,ch)`); il telefono segue il cambio canale
e il TCP sopravvive. La multi-channel beacon spam richiederebbe channel-hop
con AP down — v1 la evita di proposito.
