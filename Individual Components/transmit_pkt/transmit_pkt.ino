#include <WiFi.h>
#include "esp_wifi.h"

const char* ssid = "Zeety2";
const char* password = "Te$laxpensive!";

unsigned long start()
{
    unsigned long start_time=micros();
    return start_time;
}

void stop(unsigned long start_time)
{
    unsigned long end_time=micros();
    Serial.print(end_time-start_time);
//    Serial.println(" microseconds");
}

const uint8_t dataFrame[] = {
  // Data frame header
  0x08, 0x02,       // Frame Control
  0x00, 0x00,       // Duration
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Destination MAC
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // Source MAC
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, // BSSID
//'R','I','D',0x04, //RID type 0x04: System Message
//'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  0x00, 0x00,       // Sequence Control

  // Custom message payload
  // Insert your custom message here (up to 300 bytes)
  // For example:
  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!', // Custom message
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//    'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!', // Custom message
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//    'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!', // Custom message
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//    'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!', // Custom message
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//      'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!', // Custom message
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '4', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '5', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '6', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '7', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '8', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '9', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '0', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '1', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '2', 'W', 'o', 'r', 'l', 'd', '!',
//  'H', 'e', 'l', 'l', 'o', '3', 'W', 'o', 'r', 'l', 'd', '!',
//  'a','b',


  // Add more payload as needed in the data frame
};

const uint16_t frameLength = sizeof(dataFrame);

void setup() {
  Serial.begin(115200);

  // Connect to Wi-Fi
 WiFi.mode(WIFI_AP);

//  WiFi.softAP("Free cookies at SPAR", "dummbypassword", 1, 0, 4);

 
}

void loop() {
//    WiFi.mode(WIFI_AP);
Serial.println(frameLength);
  unsigned long start_time=start();
  // Send custom packet
  esp_wifi_80211_tx(WIFI_IF_AP, dataFrame, frameLength, false);
stop(start_time);Serial.println("");
// WiFi.mode(WIFI_OFF);
  Serial.println("Packet sent");

  delay(1000);  // Wait for 5 seconds before sending the next packet
}
