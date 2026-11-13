// RedHatSec Bridge 8266 — transparent TCP<->UART bridge per ESP8266
//
//   iPhone (orchestrator) --TCP:3333--> ESP8266 --UART0--> target hardware
//   (Proxmark3, PN532, MCU, ...)
//
// Due modalità di rete:
//   1. STA  (default): si connette all'hotspot dell'iPhone, si annuncia via
//      mDNS come _rhsbridge._tcp (l'app lo trova da sola)
//   2. AP   (fallback): se lo STA fallisce entro 20s, alza SoftAP
//      "RHS-Bridge" / "redhatsec" — l'iPhone ci entra via NEHotspotConfiguration
//      e si collega a 192.168.4.1:3333
//
// Flash: Arduino IDE → board "NodeMCU 1.0 (ESP-12E)" o "Wemos D1 mini",
//        modifica SSID/PASSWORD qui sotto, Upload.

#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>

const char *STA_SSID = "Hexxeted";
const char *STA_PASS = "lwae9180";
const char *AP_SSID  = "RHS-Bridge";
const char *AP_PASS  = "redhatsec";
const uint16_t TCP_PORT = 3333;

WiFiServer server(TCP_PORT);
WiFiClient client;

void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(false);
  pinMode(2, OUTPUT);          // LED built-in (attivo basso)
  digitalWrite(2, HIGH);

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(STA_SSID, STA_PASS);

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    digitalWrite(2, (millis() / 150) % 2);   // lampeggio: ricerca hotspot
    delay(100);
    if (millis() - t0 > 20000) break;        // fallback AP
  }

  if (WiFi.status() == WL_CONNECTED) {
    digitalWrite(2, HIGH);
    if (MDNS.begin("rhsbridge", WiFi.localIP())) {
      MDNS.addService("rhsbridge", "tcp", TCP_PORT);
    }
    Serial.printf("[bridge] STA ok ip=%s mDNS=rhsbridge.local:%u\n",
                  WiFi.localIP().toString().c_str(), TCP_PORT);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    if (MDNS.begin("rhsbridge", WiFi.softAPIP())) {
      MDNS.addService("rhsbridge", "tcp", TCP_PORT);
    }
    Serial.printf("[bridge] AP mode ssid=%s ip=%s\n",
                  AP_SSID, WiFi.softAPIP().toString().c_str());
  }

  server.begin();
  server.setNoDelay(true);
}

void loop() {
  MDNS.update();

  // un solo client alla volta (no corruzione UART)
  if (!client || !client.connected()) {
    if (client) client.stop();
    client = server.available();
    if (client) {
      client.setNoDelay(true);
      digitalWrite(2, LOW);                  // LED fisso: client attivo
      Serial.println("[bridge] client TCP connesso");
    }
  }

  // TCP -> UART
  int avail;
  while (client && client.connected() && (avail = client.available()) > 0) {
    uint8_t buf[128];
    size_t n = client.read(buf, sizeof(buf));
    if (n > 0) Serial.write(buf, n);
  }

  // UART -> TCP
  int uart;
  while (client && client.connected() && (uart = Serial.available()) > 0) {
    uint8_t buf[128];
    size_t n = Serial.readBytes(buf, sizeof(buf));
    if (n > 0) client.write(buf, n);
  }

  // LED heartbeat finché nessun client
  if (!client || !client.connected()) {
    digitalWrite(2, (millis() / 800) % 2 ? HIGH : LOW);
  }

  delay(1);
}
