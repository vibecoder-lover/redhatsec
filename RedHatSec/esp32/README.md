# RedHatBridge32 — ESP32 come modulo Wi-Fi + Bluetooth dell'iPhone

L'app parla solo **BLE** (GATT `FFE0`/`FFE1`). Il TCP dell'ESP8266 resta fallback.

## Flash (obbligatorio: partizione + 115200)

```
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=huge_app --build-property "compiler.c.elf.extra_flags=-Wl,--allow-multiple-definition" RedHatSec/esp32/RedHatBridge32
arduino-cli upload  -p COM<N> --fqbn "esp32:esp32:esp32:PartitionScheme=huge_app,UploadSpeed=115200" RedHatSec/esp32/RedHatBridge32
```

- `PartitionScheme=huge_app`: il firmware occupa ~1.68 MB, lo schema default (1.31 MB) non basta.
- `-Wl,--allow-multiple-definition` è **obbligatorio**: sovrascriviamo `ieee80211_raw_frame_sanity_check` (forte in libnet80211) per sbloccare deauth/disassoc via `esp_wifi_80211_tx`, altrimenti torna `rc=258 ESP_ERR_INVALID_ARG`.
- `UploadSpeed=115200`: sulle board clone (MAC `00:00:00:00:00:00`, rev v0.0) lo stub si perde a 921600 → `Unable to verify flash chip connection`.
- Flash diretto alternativo: `esptool write_flash 0x0 build/RedHatBridge32.ino.merged.bin`.
- Driver USB: CH340 gia' in Windows (`oem80.inf`); CP2102 = Silicon Labs VCP (Preso da Windows Update, "Silicon Laboratories Inc. - Ports - 11.2.0.167").
- Dopo il flash il banner atteso a 115200 e' `[RHS-ESP32 v1.0] BLE GATT FFE0/FFE1 pronto`.

## Requisiti radio

- Hotspot iPhone **2.4 GHz** ("Massima compatibilita'"): STA `Hexxeted` / `lwae9180` nell'ino.
- BLE + BT Classic insieme (BTDM): inquiry/SDP occupano il controller, la BLE resta su ma con latenza.
- Una sola radio Wi-Fi: deauth/PMKID/beacon sono rifiutati con rogue AP attivo (l'app lo spegne da sola).

## Protocollo (identico all'ESP8266)

```
app -> esp: [0xA5][len u16 LE][seq][cmd][payload][crc8(1, 4+len)]
esp -> app: [0x5A][len u16 LE][cmd][status][payload][crc8(1, 4+len)]
```

| cmd | funzione | payload |
|-----|----------|---------|
| 0x01 | ping | — |
| 0x02 | wifi scan | `[sec]` → `[rssi][ch][bssid6][enc][len][ssid]...` |
| 0x04 | deauth | `[mac6][ch][count]` |
| 0x05 | beacon flood | `[count][len][ssid]...` |
| 0x06 | pmkid | `[mac6][ch]` → EAPOL raw |
| 0x07 | stop | — |
| 0x08 | join rete | `[len][ssid][len][pass]` → IP |
| 0x10 | port scan | `[ip4][count][port u16]...` → `[port u16][len][banner]...` |
| 0x11/0x12 | TCP/UDP roundtrip | `[ip4][port u16][tcs][len u16][data]` |
| 0x13/0x14/0x15 | rogue start/stop/client | `[ssidLen][ssid][passLen][pass][dnsFwd]` |
| 0x16 | karma | `[on]` → CSV |
| 0x17 | captive portal | `[len u16][html]` |
| 0x18 | NAPT/DNS | `[on][dnsFwd]` |
| 0x19 | traffic log | — → `voce|voce|...` |
| 0x20 | BT Classic inquiry | `[sec]` → `[count][mac6][rssi][nameLen][name]...` |
| 0x21 | SDP | `[mac6]` → `[count][uuidLen][uuid]...` |
| 0x22 | BLE adv scan | `[sec]` → `[count][mac6][rssi][nameLen][name][advLen][adv]...` |
| 0x30 | sniff start | `[hop]` → "armed" |
| 0x31 | sniff stop | → `[ses][frames u32][eapol u32][ch]` |
| 0x32 | sniff dump idx | `[idx]` → `[bssid6][sta6][pmkid?+16][ssidLen][ssid][n][msg][len u16][frame]...` |
| 0x33 | sniff stats | → `[ses][frames u32][eapol u32][ch]` |

### Fase A — capture EAPOL/PMKID/WPS

- `0x30` promiscuous + channel hop 1–13 (350 ms/canale); con rogue AP attivo resta sul canale dell'AP.
- Memorizza fino a 6 sessioni `(BSSID, STA)` × 4 frame (EAPOL M1–M4, WPS come `msg=0`), PMKID KDE da M1, SSID da beacon/probe.
- Mutua esclusione: sniff rifiuta scan/pmkid/karma/beacon; deauth/beacon/pmkid/scan/join/rogue rifiutano con sniff attivo.
- Dump via `0x32` per indice; l'app scrive `.pcap` (DLT 127, radiotap 8B) pronto per aircrack-ng.
- Smoke test seriale su COM: `S` start hop, `R` start fisso, `R<ch>` canale forzato (es. `R6`), `Q` stop, `X` stats (canale reale hw), `D` dump con key-info, `E` deauth broadcast dall'ultimo BSSID beacon, `L` scan sincrono, `I` stato STA, `J` join con log reason.
- Verificato su hardware: deauth `rc=0`, 4-way completo M1–M4 con `ki` 0x008A/0x010A/0x13CA/0x030A.

### Fase B — BLE host-level

| Op | Comando | Payload / risposta |
|---|---|---|
| 0x40 | adv flood on/off | `[on][randAddr]` → "flood on/off" |
| 0x41 | conn flood | `[mac6][addrType][count]` → `[accepted][conns][rc lo][rc hi]` |
| 0x42 | ATT probe | `[count]` → `[sent][conns]` (0xff sent = nessuna connessione) |
| 0x43 | storm stop | → "stopped" |

- **Adv flood**: 31 byte raw random (manufacturer 0xFFFF) + rotazione indirizzo random static ogni 60 ms; al termine ripristina l'advertising FFE0 + nome.
- **Conn flood**: `esp_ble_gattc_open` diretto fino a 8 link (radio unica: il link bridge resta, ma niente Wi-Fi capture contemporanea).
- **ATT probe**: letture su handle casuali sulla connessione GATTC attiva; i risultati arrivano nel callback GATTC (`[ble] open/disc`).
- Limite reale: il fuzz resta a livello host (ATT/GATT API). PDU LL, SMP raw e L2CAP non sono raggiungibili senza controller esterno.
- Seriale: `F` toggle flood, `G` stato GATTC, `C` connect di prova a MAC fittizio, `T` probe, `H` stop.
