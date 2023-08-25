#include "Schnorr.h"
#include <SPIFFS.h>
#include "mbedtls/aes.h"
#include <esp_system.h>
#include <string.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <time.h>

#define LED_BUILTIN 2
#define NTP_SERVER "pool.ntp.org"
#define GMT_OFFSET_SEC 7200
#define DAYLIGHT_OFFSET_SEC 0
#define FrameHeaderLength 22
// The Unix timestamp for 00:00:00 01/01/2019
#define EPOCH_TIME 1546300800
uint8_t timestampBytes[4];

const int KEY_LENGTH = 64; // Length of the key in bytes
const int MAX_C1_LENGTH = 1400; // Maximum length of CPABEnonce in characters (excluding null-terminator)

char AESkey[KEY_LENGTH+1]; // Add space for null-terminator
char CPABEnonce[MAX_C1_LENGTH]; // Add space for null-terminator

int counter = 0;
char drone_uid[] = {0xde, 0xad, 0xfe, 0xed}; 
char drone_data[] = {0x0A,0x00,0x01,0x00,0x07,0xE5,0x07,0xE5,0x14,0x00,0x0A,0x00,0x01,0x00,0x07,0xE5,0x07,0xE5,0x14,0x00};
char GCS_data[] = {0xAB,0XCD,0XEF,0XFE,0XED,0XDE,0XAD,0XBA,0XDD,0XAD,0XBE,0XEF,0XDD,0XAD,0XBE,0XEF};

//missing emergency byte
//Schnorr 
unsigned char mynonce[NONCE_SIZE] = {0};
unsigned char digest[SHA256_DIGEST_LENGTH];
unsigned char public_point[64];
unsigned char R[32];
unsigned char s[32];

const uint8_t header[] = { /* Your frame header here */
//  0x08, 0x00,       // Radiotap version and pad
//  0x0E, 0x00,       // Radiotap header length (example: 14 bytes)
//  0x00, 0x00, 0x00, 0x00,  // Radiotap present flags (set to all zeros)  
    // Data frame header
  0x08, 0x02,       // Frame Control
  0x00, 0x00,       // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // Source MAC
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
uint8_t* wifiPacket;
Schnorr schnorr;

void readNextKeyValuesFromCSV() {
  

  // Open the CSV file containing the key-value pairs
  File file = SPIFFS.open("/data1.cbor");
  if (!file) {
    Serial.println("Failed to open file");
    return;
  }

  // Skip to the next set of key-value pairs based on the counter
  for (int i = 0; i < counter; i++) {
    if (!file.findUntil("\n", "\r\n")) {
      // Reached the end of the file
      Serial.println("Max limit reached");
      return;
    }
  }

  // Read the next line from the file
  String line;
  if (file.available()) {
    line = file.readStringUntil('\n');
    //line.trim();
  } else {
    // Reached the end of the file
    Serial.println("Max limit reached");
    return;
  }

  // Split the line into key and value
  int separatorIndex = line.indexOf(',');
  if (separatorIndex != -1) {
    String keyString = line.substring(0, separatorIndex);
    String c1String = line.substring(separatorIndex + 1);
  Serial.print("keystring");Serial.println(keyString);
    // Copy the key string to the char array
    strncpy(AESkey, keyString.c_str(), KEY_LENGTH);
    AESkey[KEY_LENGTH] = '\0'; // Null-terminate the key array
    
    // Copy the CPABEnonce string to the char array
    strncpy(CPABEnonce, c1String.c_str(), MAX_C1_LENGTH);
    CPABEnonce[MAX_C1_LENGTH] = '\0'; // Null-terminate the CPABEnonce array

    // Increment the counter
    counter++;
  } else {
    // Reached the end of the file
    Serial.println("Max limit reached");
  }

  // Close the file
  file.close();

//  // Deinitialize SPIFFS
//  SPIFFS.end();
}



void encrypt_ecb(char *plainText, char *hexKey, unsigned char *outputBuffer) {
  mbedtls_aes_context aes;

  mbedtls_aes_init(&aes);

  // Convert hex key to binary
  int keyLength = strlen(hexKey) / 2;
  unsigned char binaryKey[keyLength];
  for (int i = 0; i < keyLength; i++) {
    sscanf(hexKey + 2 * i, "%2hhx", &binaryKey[i]);
  }

  mbedtls_aes_setkey_enc(&aes, binaryKey, keyLength * 8);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plainText, outputBuffer);

  mbedtls_aes_free(&aes);
}

void setup() {
  Serial.begin(115200);
  // Initialize SPIFFS
  if (!SPIFFS.begin()) {
    Serial.println("Failed to mount SPIFFS");
    return;
  }
  setTimeNTP();
  // Connect to Wi-Fi
  WiFi.mode(WIFI_AP);
  WiFi.softAP("Free cookies at SPAR", "dummbypassword", 1, 0, 4);
    // Read the next key-value pair from the CSV file
  readNextKeyValuesFromCSV();
  Serial.print("Key:");
  Serial.println(AESkey);
  Serial.print("CPABEnonce:");
  Serial.println(CPABEnonce);
  getTimestamp();
  pinMode(LED_BUILTIN, OUTPUT);
 
}
unsigned long previousMillis = 0;
const unsigned long interval = 3000;
void loop() {
  // Code here will run repeatedly
  // Encrypt the GCS_data using the key
  
  unsigned long currentMillis = millis();

  if (currentMillis - previousMillis >= interval) {
  unsigned long startTime = millis();
  digitalWrite(LED_BUILTIN, HIGH);
  //long int start = millis();
  Serial.print("Key_hex:");
  schnorr.print_hex((const unsigned char*)AESkey,64);
  Serial.print("Key:");
  Serial.println(*AESkey);
  Serial.print("CPABEnonce:");
  Serial.println(CPABEnonce);
  unsigned char GCS_data_encrypted[16];
  encrypt_ecb(GCS_data, AESkey, GCS_data_encrypted);
  // Print the GCS_data_encrypted GCS_data
  Serial.print("Encrypted Message:");
  schnorr.print_hex(GCS_data_encrypted,16);
  getTimestamp();
  
  int CPABEnonceLength = strlen(CPABEnonce);
  int combinedLength = 4 + 20 + 16 + CPABEnonceLength + 4+1;
  Serial.print("Packet length:");Serial.println(FrameHeaderLength+combinedLength+64);
  uint8_t wifiPacket[FrameHeaderLength + combinedLength + 32 + 32];
  
  int index = 0;
  
  // Copy the header to wifiPacket
  memcpy(wifiPacket, header, FrameHeaderLength);
  index += FrameHeaderLength;
  // Copy drone_uid to wifiPacket
  memcpy(wifiPacket + index, drone_uid, 4);
  index += 4;
  // Copy drone_data to wifiPacket
  memcpy(wifiPacket + index, drone_data, 20);
  index += 20;
  // Copy GCS_data_encrypted to wifiPacket
  memcpy(wifiPacket + index, GCS_data_encrypted, 16);
  index += 16;
  // Copy CPABEnonce to wifiPacket
  memcpy(wifiPacket + index, CPABEnonce, CPABEnonceLength);
  index += CPABEnonceLength;
  // Copy timestampBytes to wifiPacket
  memcpy(wifiPacket + index, timestampBytes, 4);
  index += 4;
  
  schnorr.sign(wifiPacket + FrameHeaderLength, combinedLength, mynonce, wifiPacket+FrameHeaderLength+combinedLength,wifiPacket+FrameHeaderLength+combinedLength+32, public_point);
//  schnorr.sign((const unsigned char*)message, strlen(message), mynonce, R,s, public_point);
  
//  Serial.print("R:");
//  schnorr.print_hex(wifiPacket+FrameHeaderLength+combinedLength, 32);
//  Serial.print("s:");
//  schnorr.print_hex(wifiPacket+FrameHeaderLength+combinedLength+32, 32);
//  Serial.println();

  //prepare packet and send
  if (counter<100){
    esp_wifi_80211_tx(WIFI_IF_AP, wifiPacket, sizeof(wifiPacket), false);
    Serial.println("Packet sent");
    digitalWrite(LED_BUILTIN, LOW);
  }
  unsigned long endTime = millis();
  unsigned long executionTime = endTime - startTime;
  
  Serial.print("Execution time: ");
  Serial.println(executionTime);
   previousMillis = currentMillis;  // Update the previousMillis for the next iteration
   readNextKeyValuesFromCSV();
  }
  
   

}

void setTimeNTP() {
    WiFi.begin("Zeet2", "Te$laxpensive!");
    unsigned long startMillis = millis(); // Start time for connection attempt

    while (WiFi.status() != WL_CONNECTED && millis() - startMillis < 10000) {
        delay(500);
        Serial.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("WiFi connected");

        // Initialize NTP
        configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER);
        delay(1000);

        // Wait for time to be set
        time_t now = time(nullptr);
        while (now < EPOCH_TIME) {
            delay(500);
            Serial.print(".");
            now = time(nullptr);
        }
        Serial.println("Time set");
        WiFi.disconnect();
        Serial.println("Disconnected from Wi-Fi");
    } else {
        Serial.println("Wi-Fi connection failed. Setting time manually.");
        setManualTime();
    }
}

void getTimestamp() {
    time_t now = time(nullptr);
    if (now < EPOCH_TIME) {
      Serial.println("Time not set or invalid");
      return;
    }
    uint32_t currentTimestamp = now ; // Unix timestamp in seconds since 00:00:00 01/01/2019
    timestampBytes[0] = (uint8_t)(currentTimestamp >> 24);
    timestampBytes[1] = (uint8_t)(currentTimestamp >> 16);
    timestampBytes[2] = (uint8_t)(currentTimestamp >> 8);
    timestampBytes[3] = (uint8_t)(currentTimestamp);
    Serial.print("Current timestamp: ");
    Serial.println(currentTimestamp);
}

void setManualTime() {
    struct tm timeinfo;
    timeinfo.tm_year = 2023 - 1900;
    timeinfo.tm_mon = 0;
    timeinfo.tm_mday = 1;
    timeinfo.tm_hour = 0;
    timeinfo.tm_min = 0;
    timeinfo.tm_sec = 0;
    time_t epochTime = mktime(&timeinfo);
    struct timeval tv = { .tv_sec = epochTime };
    settimeofday(&tv, nullptr);
    Serial.println("Time set manually.");
}
