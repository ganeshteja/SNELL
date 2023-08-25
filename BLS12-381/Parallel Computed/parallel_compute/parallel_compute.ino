

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bls_BLS12381.h>
#include "esp_system.h"
#include "esp_random.h"
#include <randapi.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "mbedtls/aes.h"
#include "Schnorr.h"

using namespace core;
using namespace BLS12381;
using namespace BLS12381_FP;
using namespace BLS12381_BIG;

SET_LOOP_TASK_STACK_SIZE(17*1024);

//Schnorr related variables
unsigned char mynonce[NONCE_SIZE] = {0};
unsigned char digest[SHA256_DIGEST_LENGTH];
unsigned char public_point[64];
Schnorr schnorr;


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



const int arraySize = 12;
int rows[arraySize][arraySize] = {
    {1, 1, 1, 1, 1, 1, 1, 1, 1},
    {1, 1, 1, 1, 1, 1, 1, 1, 1},
    {0, 0, 0, 0, 0, 0, 0, 0, -1},
    {0, 0, 0, 0, 0, 0, 0, -1},
    {0,0,0,0,0,0,-1},
    {0,0,0,0,0,-1},
    {0,0,0,0,-1},
    {1,1,1,1},
    {0,0,0,-1},
    {0,0,-1},
    {0,-1},
    {1}
};


char policy[] = {"NL or US and Civ and Op and A4 and A5 and A6 or A7 and A8 and A9 and A10 or Gov"};
char attributes[arraySize][5] = {"NL", "US", "Civ", "Op","A4","A5","A6","A7","A8","A9","A10","Gov"};
char GTchar[MODBYTES_B384_29  * 12];
octet GTOctet = {0,MODBYTES_B384_29  * 12,GTchar};  
int policy_len = 87;
int totalLength = 62+770+arraySize*49+policy_len+5+64;
char combinedCharArray[62+770+arraySize*49+87+5+64];

      
csprng RNG;                // Crypto Strong RNG
//FABEO related materials
ICACHE_RAM_ATTR BIG r,s0,s1,mys0;
ICACHE_RAM_ATTR BIG v[arraySize];
ICACHE_RAM_ATTR ECP bHash,myg1,attr_Hash[arraySize],ct[arraySize];
ICACHE_RAM_ATTR ECP2 pkh,g_s0,h_s1,myg2;
ICACHE_RAM_ATTR FP12 rnonce, eghAlpha, Cp;
ICACHE_RAM_ATTR volatile bool core1_computed = false;
ICACHE_RAM_ATTR int current_pos =0;
//drone related data
char drone_uid[] = {0xde, 0xad, 0xfe, 0xed}; 
char drone_data[] = {0x0A,0x00,0x01,0x00,0x07,0xE5,0x07,0xE5,0x14,0x00,0x0A,0x00,0x01,0x00,0x07,0xE5,0x07,0xE5,0x14,0x00};
uint8_t GCS_data[] = {0xAB,0XCD,0XEF,0XFE,0XED,0XDE,0XAD,0XBA,0XDD,0XAD,0XBE,0XEF,0XDD,0XAD,0XBE,0XEF};

//wifi packet header
const uint8_t header[] = { 
// Data frame header
  0x08, 0x02,       // Frame Control
  0x00, 0x00,       // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // Source MAC
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };


/*
 * intialize the public key's G2 point
 */

void init_pkh() {
BIG_randomnum(mys0, r, &RNG);
ECP2_generator(&pkh);
PAIR_G2mul(&pkh, mys0);
//ECP2_copy(&pkh,&myg2);

    (PAIR_G2member(&pkh)==1)? Serial.println("pkh on G2"): Serial.println("pkh not on G2");


}


/*
 * intialize the public key's GT point
 */
void init_eghAlpha(){
BIG_randomnum(mys0, r, &RNG);
ECP_generator(&myg1);
ECP2_generator(&myg2);
PAIR_G1mul(&myg1, mys0);
PAIR_G2mul(&myg2, mys0); 
PAIR_ate(&eghAlpha, &myg2, &myg1);
PAIR_fexp(&eghAlpha);

  (PAIR_GTmember(&eghAlpha)==1)? Serial.println("ëgh_alpha_init on GT"): Serial.println("ëgh_alpha_init not on GT");


}

/*
 * compute hashes of the curve_order+1 and the attributes in the policy and map them to points on G1 
 */
void compute_hashes(){
  Serial.println(" ");
  Serial.print("time for hash");unsigned long start_time=start();
  BIG order;
  char orderChar[MODBYTES_B384_29];
  BIG_rcopy(order, CURVE_Order);
  BIG_inc(order,1);
  BIG_toBytes(orderChar, order);
  octet orderOctet = {strlen(orderChar), MODBYTES_B384_29, orderChar};
  Serial.println();Serial.print("orderOctet:");Serial.println(orderOctet.len);
  //compute bHash
  BLS_HASH_TO_POINT(&bHash, &orderOctet);Serial.println(""); 
  Serial.print("bHash:");ECP_output(&bHash);Serial.println("");
  OCT_output(&orderOctet);Serial.println("");
  
  //compute attr_Hash
  for (int i=0;i<arraySize;i++){
    octet attr = {strlen(attributes[i]), sizeof(attributes[i]), attributes[i]};
    BLS_HASH_TO_POINT(&attr_Hash[i], &attr); 
    Serial.print("attr_Hash[i]:");ECP_output(&attr_Hash[i]);Serial.println("");
      }
    stop(start_time);Serial.println("");
  
}
/*
 * Compute KDF from the G2 rnonce point
 */

void computeKDF(FP12* input, uint8_t* derivedKey)
{
    int keyLength = 16; // Desired key length in bytes
    char orderChar[MODBYTES_B384_29 * 12];
    octet outputOctet = {0, MODBYTES_B384_29 * 12, orderChar};

    FP12_toOctet(&outputOctet, input);
    octet keyOctet = {0, keyLength, (char*)derivedKey};
    octet* params = NULL;

    // Perform the KDF2 operation
    KDF2(MC_SHA2, SHA256, &keyOctet, keyLength, &outputOctet, params);
}

/*
 * Encrypt the input palintext with the given key using AES ECB mode and put it in the buffer
 */
void encrypt_ecb(uint8_t* plainText, uint8_t* key, uint8_t* outputBuffer) {
  mbedtls_aes_context aes;

  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 16 * 8);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plainText, outputBuffer);
  mbedtls_aes_free(&aes);
}

/*
 * Compute rnonce, gs0-hs1, Cp in parallel on core 1, while the other core is computing ct.
 * Also perform the AES encryption and write data to the array
 */
 
void compute_parallel(void* parameter){

core1_computed = false;
//  Serial.print ("running parallel in core ");
//  Serial.println (xPortGetCoreID());
unsigned long start_time=start();

//generate s0,s1,v[]

//start_time=start();
BIG_randomnum(s0, r, &RNG);
//Serial.print("s0:");BIG_output(s0);Serial.println("");
BIG_randomnum(s1, r, &RNG);
//Serial.print("s1:");BIG_output(s1);Serial.println("");
BIG_rcopy(v[0],s0);
for (int i=1;i<arraySize;i++){
  BIG_randomnum(v[i], r, &RNG);
}
//Serial.print("s0s1v[] comp time:");stop(start_time);Serial.print(",");

//compute g_s0,h_s1

//start_time=start();
ECP2_copy(&g_s0,&pkh);
ECP2_copy(&h_s1,&pkh);
PAIR_G2mul(&g_s0, s0);
PAIR_G2mul(&h_s1, s1); 
//Serial.print("gs0,hs1 comp time:");stop(start_time);Serial.print(",");
//(PAIR_G2member(&g_s0)==1)? Serial.println("g_s0 on G2") : Serial.println("g_s0 not on G2");
//(PAIR_G2member(&h_s1)==1)? Serial.println("h_s1 on G2"): Serial.println("h_s1 not on G2");
////Serial.print("gs0:");ECP2_output(&g_s0);Serial.print(",");


//compute ct[] till 4

//start_time=start();
int num_itr=7;


for (int j=0;j<num_itr;j++){
  BIG Mivtop;
  BIG_zero(Mivtop);
  for (int k=0;k<arraySize;k++){
    if (rows[j][k] ==1){
      BIG_add(Mivtop,Mivtop,v[k]);
    }
    if (rows[j][k] ==-1){
      BIG_sub(Mivtop,Mivtop,v[k]);
    }
  }
  // calculate bHash ** Mivtop
  ECP temp1;
  ECP_copy(&temp1, &bHash);
  PAIR_G1mul(&temp1, Mivtop);
  
  // calculate attrHash[j] ** s1
  ECP temp2;
  ECP_copy(&temp2, &attr_Hash[j]);
  PAIR_G1mul(&temp2, s1);
  
  // Calculate the final ct[] = (bHash ** Mivtop) * (attrHash[j] ** s1)
  ECP_copy(&ct[j], &temp1);
  ECP_add(&ct[j], &temp2); // ct[attr] = temp1 + temp2
//  (PAIR_G1member(&ct[j])==1)? Serial.print(""): Serial.println("ct[j] not on G1");
}
//Serial.print("ct 1st half computation time");stop(start_time);Serial.print(",");

//compute Cp

//start_time=start();
FP12_pow(&Cp,&eghAlpha,s0);
//FP12_copy(&Cp,&eghAlpha);
//PAIR_GTpow(&Cp,s0);
FP12_mul(&Cp,&rnonce);
//Serial.print("Cp comp time:");stop(start_time);Serial.print(",");

//Serial.print("finished jobs on core 0");
//(PAIR_GTmember(&Cp)==1)?Serial.println("Cp on GT") : Serial.println("Cp not on GT");

core1_computed = true;
vTaskDelete(NULL);
}



void setup() {
  int i;
  
  Serial.begin(115200);
    while (!Serial);
     WiFi.softAP("LGqHDTV+", "dummbypassword", 1, 0, 4);
     Serial.print ("starting in core ");
    Serial.println (xPortGetCoreID());
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    RAW.len = 100;
//    for (i = 0; i < 100; i++) RAW.val[i] = i + 1;
    esp_fill_random(raw, sizeof(raw));
    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG
    
    //copy headers and other drone data
memcpy(combinedCharArray+current_pos,header,22);
    current_pos += 22;
memcpy(combinedCharArray+current_pos,drone_uid,4);
    current_pos += 4;
memcpy(combinedCharArray+current_pos,drone_data,20);
    current_pos += 20;
   
   
BIG_rcopy(r, CURVE_Order);

//initalize pkh
init_pkh();

//initalize eghAlpha
init_eghAlpha();

// compute bHash and attrHash[]  
compute_hashes();


Serial.println("Starting loop");

for(int a=0;a<100;a++){
  Serial.print(a);Serial.print(",");
  unsigned long total_time=start();

TaskHandle_t taskHandle;

xTaskCreatePinnedToCore(compute_parallel, "compute_parallel", 10000, NULL, 1, &taskHandle, 0);
vTaskResume(taskHandle);    

//unsigned long start_time=start();


// Generate random nonce
ECP myg1;
ECP2 myg2;
uint8_t rnonce_key[16];
uint8_t GCS_data_encrypted[16];

BIG_randomnum(s0, r, &RNG);
ECP_generator(&myg1);
ECP2_generator(&myg2);
PAIR_G1mul(&myg1, s0);
PAIR_G2mul(&myg2, s0); 
PAIR_ate(&rnonce, &myg2, &myg1);
PAIR_fexp(&rnonce);
//Serial.print("rnonce comp time:");stop(start_time);Serial.print(",");

//start_time=start();
computeKDF(&rnonce,rnonce_key);
encrypt_ecb(GCS_data,(uint8_t*)rnonce_key,(uint8_t*)GCS_data_encrypted);
current_pos = 46; 
memcpy(combinedCharArray+current_pos,GCS_data_encrypted,16);
    current_pos += 16; 
//Serial.print("rnoncekey comp time:");stop(start_time);Serial.print(",");
//(PAIR_GTmember(&rnonce)==1)? Serial.println("rnonce on G2") : Serial.println("rnonce not on G2");




//compute ct[]



//start_time=start();
int num_itr=7;

for (int j=num_itr;j<arraySize;j++){
  BIG Mivtop;
  BIG_zero(Mivtop);
  for (int k=0;k<arraySize;k++){
    if (rows[j][k] ==1){
      BIG_add(Mivtop,Mivtop,v[k]);
    }
    if (rows[j][k] ==-1){
      BIG_sub(Mivtop,Mivtop,v[k]);
    }
  }
  // calculate bHash ** Mivtop
  ECP temp1;
  ECP_copy(&temp1, &bHash);
  PAIR_G1mul(&temp1, Mivtop);
  
  // calculate attrHash[j] ** s1
  ECP temp2;
  ECP_copy(&temp2, &attr_Hash[j]);
  PAIR_G1mul(&temp2, s1);
  
  // Calculate the final ct[] = (bHash ** Mivtop) * (attrHash[j] ** s1)
  ECP_copy(&ct[j], &temp1);
  ECP_add(&ct[j], &temp2); // ct[attr] = temp1 + temp2
//  (PAIR_G1member(&ct[j])==1)? Serial.print(""): Serial.println("ct[j] not on G1");
}
//Serial.print("ct 2nd half computation time:");stop(start_time);Serial.print(",");
current_pos =62;
char G2char[MODBYTES_B384_29  * 2 +1];
    octet G2Octet = {0,MODBYTES_B384_29  * 2 +1,G2char};
    
    ECP2_toOctet(&G2Octet,&g_s0,true);
    memcpy(combinedCharArray+current_pos,G2Octet.val,G2Octet.len);
    current_pos += G2Octet.len;


    OCT_clear(&G2Octet);
    ECP2_toOctet(&G2Octet,&h_s1,true);
    memcpy(combinedCharArray+current_pos,G2Octet.val,G2Octet.len);
    current_pos += G2Octet.len;

//start_time=start();
while(!core1_computed){delay(1);};
//Serial.print("wait time for sync:");stop(start_time);Serial.print(",");

//start_time=start();



    OCT_clear(&GTOctet);
    FP12_toOctet(&GTOctet,&Cp);
    memcpy(combinedCharArray+current_pos,GTOctet.val,GTOctet.len);
    current_pos += GTOctet.len;

char G1char[MODBYTES_B384_29+1];
    octet G1Octet = {0,MODBYTES_B384_29+1,G1char};
    for (int j=0;j<arraySize;j++){
      OCT_clear(&G1Octet);
      ECP_toOctet(&G1Octet,&ct[j],true);
      memcpy(combinedCharArray+current_pos,G1Octet.val,G1Octet.len);
      current_pos += G1Octet.len;

    }
    memcpy(combinedCharArray+current_pos,policy,policy_len);
      current_pos += policy_len;
    
//Serial.print("packet assembly:");stop(start_time);Serial.print(",");



//start_time=start(); 
schnorr.sign((const unsigned char*)combinedCharArray + 22, totalLength-86, mynonce,(unsigned char*) combinedCharArray+62+770+arraySize*49+5+policy_len,(unsigned char*)combinedCharArray+62+770+arraySize*49+5+policy_len+32, public_point);
//Serial.print("schnorr:"); stop(start_time);Serial.print(",");  
 

//start_time=start(); 
  combinedCharArray[totalLength] = '\0';
esp_wifi_80211_tx(WIFI_IF_AP, combinedCharArray, sizeof(combinedCharArray), false);
// Serial.print("wifi txn:"); stop(start_time);Serial.println(""); 
 
//  for (int i = 0; i < totalLength; i++) {
//    if (combinedCharArray[i] < 16) {
//        Serial.print("0");
//    }
//    Serial.print(combinedCharArray[i], HEX);
////    Serial.print(" ");
//}
//Serial.println("");

Serial.print("total time taken:");stop(total_time);Serial.println(",");
    
  }
}
void loop() {
  // put your main code here, to run repeatedly:

}
