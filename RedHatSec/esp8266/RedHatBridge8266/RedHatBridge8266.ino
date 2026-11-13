// RedHatSec Bridge 8266 — AP-only, transparent TCP<->UART bridge per ESP8266
//
//   iPhone (orchestrator) --TCP:3333--> ESP8266 --UART0--> target hardware
//   (Proxmark3, PN532, MCU, ...)
//
// Modalità: SOLO SoftAP. All'avvio alza l'AP "RHS-Bridge" (pass "redhatsec"),
// l'iPhone ci entra una volta dalle Impostazioni (poi si riaggancia da solo) e
// l'app si connette automaticamente a 192.168.4.1:3333.
//
// Flash: Arduino IDE → board "NodeMCU 1.0 (ESP-12E)" o "Wemos D1 mini" → Upload.

#include <ESP8266WiFi.h>

const char *AP_SSID  = "RHS-Bridge";
const char *AP_PASS  = "redhatsec";
const uint16_t TCP_PORT = 3333;

WiFiServer server(TCP_PORT);
WiFiClient client;

void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(false);
  pinMode(2, OUTPUT);
  digitalWrite(2, LOW);            // LED: AP attivo

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(100);

  server.begin();
  server.setNoDelay(true);
  Serial.printf("[bridge] AP '%s' pass '%s' ip %s :%u pronto\n",
                AP_SSID, AP_PASS,
                WiFi.softAPIP().toString().c_str(), TCP_PORT);
}

void loop() {
  // un solo client alla volta (no corruzione UART)
  if (!client || !client.connected()) {
    if (client) client.stop();
    client = server.available();
    if (client) {
      client.setNoDelay(true);
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

  // LED: fisso con client, lampeggio in attesa
  if (!client || !client.connected()) {
    digitalWrite(2, (millis() / 800) % 2 ? LOW : HIGH);
  } else {
    digitalWrite(2, LOW);
  }

  delay(1);
}
