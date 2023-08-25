#include <SPIFFS.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bls_BLS12381.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <randapi.h>
using namespace core;
using namespace BLS12381;
using namespace BLS12381_FP;
using namespace BLS12381_BIG;


SET_LOOP_TASK_STACK_SIZE(17*1024);
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

csprng RNG;  
BIG r,s0;
FP12 rnonce;
char GTchar[MODBYTES_B384_29  * 12];
octet GTOctet = {0,MODBYTES_B384_29  * 12,GTchar};  
char b64[784];
int file_pos =0;

/*
* Precompute ranodom nonces on GT and save them to a file on SPIFFS
*/
void precompute_rnonce(){
ECP myg1;
ECP2 myg2;
Serial.print("Computing rnonces:");
unsigned long start_time=start();
// Generate random nonce
File file = SPIFFS.open("/rnonces_bls12381.txt", FILE_WRITE);
if (file){
  for(int i=0;i<100;i++){
    
    BIG_randomnum(s0, r, &RNG);
    ECP_generator(&myg1);
    ECP2_generator(&myg2);
    PAIR_G1mul(&myg1, s0);
    PAIR_G2mul(&myg2, s0); 
    PAIR_ate(&rnonce, &myg2, &myg1);
    PAIR_fexp(&rnonce);
    Serial.print(i);
    Serial.print(" rnonce:");
    FP12_output(&rnonce);Serial.println();
    OCT_clear(&GTOctet);
    FP12_toOctet(&GTOctet,&rnonce);
    OCT_tobase64(b64,&GTOctet);
    file.write((const uint8_t*)b64, 784);
    
    }
   file.close();
  }
  
 else {
    Serial.println("Failed to open file for writing");
  }

stop(start_time);Serial.println("");
}


void get_rnonce(){
  File file = SPIFFS.open("/rnonces_bls12381.txt", FILE_READ);
  if (file) {
      file.seek(file_pos);
      file.read((uint8_t*)b64, 784);

      // Convert base64 string to octet
      OCT_frombase64(&GTOctet,b64);
      FP12_fromOctet(&rnonce,&GTOctet);
      file_pos +=784;
    
    file.close();
    Serial.print("got rnonce:");
    FP12_output(&rnonce);
  } else {
    Serial.println("Failed to open file for reading");
  }
}


void setup(){
Serial.begin(115200);
while (!Serial);

WiFi.softAP("LGqHDTV+", "dummbypassword", 1, 0, 4);
SPIFFS.begin();

char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    RAW.len = 100;
    esp_fill_random(raw, sizeof(raw));
    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG
    BIG_rcopy(r, CURVE_Order);

delay(5000);
precompute_rnonce();

Serial.println();
for(int i=0;i<100;i++){
  get_rnonce();
  Serial.println();
}



}




void loop(){

}
