#include <SPIFFS.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bls_BN254.h>
#include "esp_system.h"
#include "esp_random.h"
#include <randapi.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "mbedtls/aes.h"
#include "Schnorr.h"
#include "FS.h"

using namespace core;
using namespace BN254;
using namespace BN254_FP;
using namespace BN254_BIG;

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




const int arraySize = 23;


int rows[arraySize][arraySize] = {
{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1}, 
{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1}, 
{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1}, 
 {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1}, 
 {0, 0, 0, 0, 0, 0, 0, 0, 0, -1}, 
 {1, 1, 1, 1, 1, 1, 1, 1, 1}, 
 {0, 0, 0, 0, 0, 0, 0, 0, -1},
 {0, 0, 0, 0, 0, 0, 0, -1}, 
 {0, 0, 0, 0, 0, 0, -1},
{0, 0, 0, 0, 0, -1}, 
{1, 1, 1, 1, 1},
{0, 0, 0, 0, -1},
 {0, 0, 0, -1}, 
 {0, 0, -1},
{0, -1}, 
{1}};

char policy[] = {"NL|US&Civ&Op&A4&A5&A6|A7&A8&A9&A10&A11|Gov&Op1&A41&A51&A61|A71&A81&A91&A101&A111|Gov1"};
char attributes[arraySize][5] = {"NL","US","Civ","Op","A4","A5","A6","A7","A8","A9","A10","A11","Gov","Op1","A41","A51","A61","A71","A81","A91","A101","A111","Gov1"};


char GTchar[MODBYTES_B256_28  * 12];
octet GTOctet = {0,MODBYTES_B256_28  * 12,GTchar};  
int policy_len = 87;
int totalLength = 62+514+arraySize*33+policy_len+5+64;
char combinedCharArray[62+514+arraySize*33+87+5+64];
char b64[512];
int file_pos =0;
      
csprng RNG;                // Crypto Strong RNG
//FABEO related materials
BIG r,s0,s1;
BIG v[arraySize];
ECP bHash,attr_Hash[arraySize],ct[arraySize];
ECP2 pkh,g_s0,h_s1;
FP12 rnonce, eghAlpha, Cp, Cp1;

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
    // The coordinates
char xcoord1[] ={0x14, 0x6b, 0xe3, 0xca, 0x42, 0xfd, 0xcd, 0xa1, 0x09, 0x14, 0x62, 0x73, 0x98, 0x96, 0x3b, 0x9c, 0x24, 0xb7, 0x83, 0xea, 0x5c, 0x82, 0x80, 0xee, 0xb0, 0xa4, 0x22, 0xcf, 0x13, 0xa4, 0x2c, 0x79};
char xcoord2[] ={0x1c, 0x9c, 0xaa, 0x91, 0xdc, 0xba, 0xe8, 0x09, 0x7f, 0x95, 0xa2, 0xc2, 0xb0, 0x8f, 0xe5, 0xdf, 0x1a, 0x81, 0xd1, 0x21, 0x91, 0x63, 0x5c, 0x4b, 0x98, 0x45, 0x47, 0xc6, 0xfb, 0x08, 0xd7, 0x38};
char ycoord1[] ={0x09, 0xa3, 0x70, 0x4a, 0x8f, 0xb2, 0xaf, 0xd4, 0xef, 0x1d, 0x71, 0xbf, 0x87, 0x75, 0x5a, 0xba, 0xc5, 0x43, 0x87, 0xda, 0x9b, 0x62, 0x9d, 0x44, 0x9a, 0x68, 0xec, 0x19, 0x3f, 0x0f, 0x13, 0x84};
char ycoord2[] ={0x02, 0xb2, 0xf4, 0x97, 0x24, 0x2f, 0xa3, 0xf5, 0x27, 0x58, 0x45, 0xb9, 0x27, 0xfe, 0xe9, 0x51, 0x1b, 0xca, 0x7a, 0x0e, 0x76, 0x6c, 0x3f, 0x32, 0x17, 0x5a, 0x68, 0x2d, 0x43, 0x34, 0x26, 0x3e};

    // Init the coordinates
    BIG ax, bx, ay, by;
    BIG_fromBytes(ax,xcoord1);
    BIG_fromBytes(bx,xcoord2);
    BIG_fromBytes(ay,ycoord1);
    BIG_fromBytes(by,ycoord2);

    // Create the FP2 coordinates
    FP2 x, y;
    FP2_from_BIGs(&x, ax, bx);
    FP2_from_BIGs(&y, ay, by);
    ECP2_set(&pkh, &x,&y);
    (PAIR_G2member(&pkh)==1)? Serial.println("pkh on G2"): Serial.println("pkh not on G2");

}


/*
 * intialize the public key's GT point
 */
void init_eghAlpha(){
  char values[3][2][2][32]={
 { //A
  {{0x06, 0x2d, 0xff, 0xff, 0x04, 0xf0, 0x81, 0x59, 0x69, 0xab, 0xa2, 0x96, 0x7b, 0xda, 0xfa, 0xfb, 0x85, 0x32, 0xeb, 0xbe, 0xe0, 0xef, 0x3f, 0xed, 0xad, 0xe6, 0x42, 0x6f, 0x8e, 0x87, 0x6c, 0x05 },
  {0x05, 0xde, 0xd2, 0x9a, 0xad, 0xaf, 0x17, 0x70, 0x4c, 0x04, 0x0f, 0x75, 0xfb, 0x41, 0xc4, 0x9a, 0x35, 0x95, 0x95, 0x76, 0x21, 0x7d, 0x55, 0xa5, 0xe7, 0xc6, 0x9d, 0x2d, 0xf7, 0xef, 0x86, 0xea }},
  {{0x17, 0x26, 0xf1, 0xe9, 0x9e, 0x42, 0x99, 0x38, 0x4e, 0x0c, 0x8d, 0x8f, 0x9b, 0x37, 0x83, 0x0e, 0x23, 0x81, 0x8d, 0x4f, 0x6e, 0x20, 0xd4, 0x25, 0x97, 0x15, 0xef, 0x1b, 0xfa, 0x72, 0x67, 0xfb },
  {0x11, 0x02, 0x34, 0x66, 0xc2, 0x2c, 0xed, 0x20, 0x2e, 0x7d, 0x45, 0x7f, 0x4a, 0xf1, 0xb9, 0x59, 0xe7, 0x9e, 0x2b, 0xba, 0xc6, 0xc5, 0xcb, 0xef, 0x88, 0x93, 0x4f, 0x8c, 0xe2, 0x86, 0xa3, 0x40 }}
  },
  { //B
  {{0x03, 0x0e, 0x0e, 0x40, 0x4a, 0x62, 0xee, 0xe5, 0x64, 0x92, 0x86, 0xdb, 0x6a, 0x6a, 0xbd, 0x9c, 0x54, 0xff, 0x81, 0xf4, 0xa1, 0x22, 0x9d, 0x90, 0xf6, 0x60, 0x97, 0x99, 0x71, 0x19, 0x96, 0xb8 },
  {0x21, 0x7a, 0x2e, 0x66, 0x60, 0x20, 0x99, 0x0a, 0xa0, 0x5e, 0x38, 0x17, 0xbc, 0xa3, 0xf7, 0x3e, 0x07, 0x62, 0xd9, 0x71, 0x36, 0x03, 0xc2, 0x0d, 0x86, 0x12, 0x29, 0x58, 0x23, 0xb1, 0x34, 0xd8 }},
  {{0x0d, 0xeb, 0xd2, 0x9a, 0x30, 0xc3, 0xa6, 0x87, 0x08, 0x13, 0xfd, 0x61, 0xd7, 0x6e, 0xde, 0x76, 0xe6, 0x98, 0x69, 0x90, 0x68, 0x0e, 0x6a, 0x1e, 0x7a, 0x31, 0x15, 0xcb, 0x73, 0x76, 0x53, 0x0f },
  {0x14, 0xdc, 0x3b, 0x4e, 0x00, 0xc7, 0xf8, 0x02, 0x35, 0x45, 0x8e, 0x17, 0xfe, 0x05, 0x6a, 0x1f, 0xec, 0x47, 0xf8, 0x84, 0x24, 0x29, 0x71, 0xbd, 0xf6, 0x4a, 0x85, 0x3c, 0x04, 0x60, 0x7b, 0xd2 }}
  },
  { //C
  {{0x14, 0x7f, 0x75, 0x4b, 0x4b, 0xd3, 0x7a, 0x70, 0x1d, 0x54, 0x92, 0x90, 0x76, 0x74, 0xfe, 0x0b, 0x24, 0x8c, 0x10, 0xb4, 0x30, 0x7a, 0xc3, 0x1c, 0x2e, 0x89, 0x79, 0x3e, 0xee, 0x73, 0x17, 0xe9, },
  {0x08, 0xf7, 0x9c, 0x94, 0x0c, 0x64, 0x22, 0x70, 0x28, 0x6f, 0x02, 0x93, 0x39, 0x7c, 0xf9, 0x05, 0x56, 0xe0, 0xd0, 0xf2, 0x05, 0x7c, 0x82, 0x0b, 0xa0, 0x29, 0xdc, 0x5b, 0x9b, 0xb0, 0x68, 0x97, }},
  {{0x07, 0xae, 0xd0, 0xef, 0xdc, 0xe1, 0xbf, 0x1f, 0x9f, 0x59, 0x6f, 0x92, 0x2d, 0x74, 0xbe, 0x22, 0x29, 0x04, 0x38, 0xf8, 0x3b, 0x9f, 0xeb, 0xcf, 0x9c, 0x8b, 0x0a, 0xb9, 0x36, 0xde, 0x34, 0x99, },
  {0x09, 0x38, 0x60, 0x45, 0xa8, 0x82, 0x50, 0x12, 0x77, 0x3b, 0x94, 0xa8, 0x46, 0x3d, 0x84, 0x55, 0xa4, 0xdd, 0x4a, 0x69, 0xf3, 0x07, 0x37, 0xcc, 0xd3, 0x14, 0xfd, 0x00, 0x0d, 0xe5, 0xf3, 0x56, }}
  }

};
  FP4 fp4s[3];

  for(int i=0;i<3;i++){
    FP2 fp2s[2];
    for(int j=0;j<2;j++){
      BIG v1,v2;
      BIG_fromBytes(v1,values[i][j][0]);
      BIG_fromBytes(v2,values[i][j][1]);
      FP2_from_BIGs(&fp2s[j],v1,v2);
    }
    FP4_from_FP2s(&fp4s[i],&fp2s[0],&fp2s[1]);
  }
  FP12_from_FP4s(&eghAlpha,&fp4s[0],&fp4s[1],&fp4s[2]);
  (PAIR_GTmember(&eghAlpha)==1)? Serial.println("ëgh_alpha_init on GT"): Serial.println("ëgh_alpha_init not on GT");


}

/*
 * compute hashes of the curve_order+1 and the attributes in the policy and map them to points on G1 
 */
void compute_hashes(){
  Serial.println(" ");
  Serial.print("time for hash");unsigned long start_time=start();
  BIG order;
  char orderChar[MODBYTES_B256_28];
  BIG_rcopy(order, CURVE_Order);
  BIG_inc(order,1);
  BIG_toBytes(orderChar, order);
  octet orderOctet = {strlen(orderChar), MODBYTES_B256_28, orderChar};
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
    char orderChar[MODBYTES_B256_28 * 12];
    octet outputOctet = {0, MODBYTES_B256_28 * 12, orderChar};

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


void setup() {
  int i;
  int current_pos =0;
  Serial.begin(115200);
    while (!Serial);
     WiFi.softAP("TestAP", "dummbypassword", 1, 0, 4);
     if (!SPIFFS.begin(true)) {
    Serial.println("An error occurred while mounting SPIFFS");
    return;
  }
  else{
    Serial.println("mounted SPIFFS");
  }
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
unsigned long start_time=start();
// Generate random nonce

uint8_t rnonce_key[16];
uint8_t GCS_data_encrypted[16];
File file = SPIFFS.open("/r_nonces.txt", FILE_READ);
if (file) {
      file.seek(file_pos);
      file.read((uint8_t*)b64, 512);

      // Convert base64 string to octet
      OCT_frombase64(&GTOctet,b64);
      FP12_fromOctet(&rnonce,&GTOctet);
      file_pos +=512;
    
    file.close();
//    Serial.print("got rnonce:");
//    FP12_output(&rnonce);
  } else {
    Serial.println("Failed to open file for reading");
  }
Serial.print("rnonce comp time:");stop(start_time);Serial.print(",");

start_time=start();
computeKDF(&rnonce,rnonce_key);
encrypt_ecb(GCS_data,(uint8_t*)rnonce_key,(uint8_t*)GCS_data_encrypted);
current_pos = 46; 
memcpy(combinedCharArray+current_pos,GCS_data_encrypted,16);
    current_pos += 16; 
Serial.print("rnoncekey comp time:");stop(start_time);Serial.print(",");
//(PAIR_GTmember(&rnonce)==1)? Serial.println("rnonce on GT") : Serial.println("rnonce not on GT");



//generate s0,s1,v[]
//
start_time=start();
BIG_randomnum(s0, r, &RNG);
//Serial.print("s0:");BIG_output(s0);Serial.println("");
BIG_randomnum(s1, r, &RNG);
//Serial.print("s1:");BIG_output(s1);Serial.println("");
BIG_rcopy(v[0],s0);
for (i=1;i<arraySize;i++){
  BIG_randomnum(v[i], r, &RNG);
}
Serial.print("s0_s1_v[] comp time:");stop(start_time);Serial.print(",");


//compute g_s0,h_s1
//
start_time=start();
ECP2_copy(&g_s0,&pkh);
ECP2_copy(&h_s1,&pkh);
PAIR_G2mul(&g_s0, s0);
PAIR_G2mul(&h_s1, s1); 
Serial.print("gs0_hs1 comp time:");stop(start_time);Serial.print(",");
//(PAIR_G2member(&g_s0)==1)? Serial.println("g_s0 on G2") : Serial.println("g_s0 not on G2");
//(PAIR_G2member(&h_s1)==1)? Serial.println("h_s1 on G2"): Serial.println("h_s1 not on G2");

//compute Cp
//
start_time=start();
FP12_pow(&Cp,&eghAlpha,s0);
//FP12_copy(&Cp,&eghAlpha);
//PAIR_GTpow(&Cp,s0);
FP12_mul(&Cp,&rnonce);
Serial.print("Cp comp time:");stop(start_time);Serial.print(",");
//(PAIR_GTmember(&Cp)==1)?Serial.println("Cp on GT") : Serial.println("Cp not on GT");


//compute ct[]
//
start_time=start();
for (int j=0;j<arraySize;j++){
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
Serial.print("ct computation time:");stop(start_time);Serial.print(",");

start_time=start();
current_pos =62;
char G2char[MODBYTES_B256_28  * 2 +1];
    octet G2Octet = {0,MODBYTES_B256_28  * 2 +1,G2char};
    
    ECP2_toOctet(&G2Octet,&g_s0,true);
    memcpy(combinedCharArray+current_pos,G2Octet.val,G2Octet.len);
    current_pos += G2Octet.len;


    OCT_clear(&G2Octet);
    ECP2_toOctet(&G2Octet,&h_s1,true);
    memcpy(combinedCharArray+current_pos,G2Octet.val,G2Octet.len);
    current_pos += G2Octet.len;


    OCT_clear(&GTOctet);
    FP12_toOctet(&GTOctet,&Cp);
    memcpy(combinedCharArray+current_pos,GTOctet.val,GTOctet.len);
    current_pos += GTOctet.len;

char G1char[MODBYTES_B256_28+1];
    octet G1Octet = {0,MODBYTES_B256_28+1,G1char};
    for (int j=0;j<arraySize;j++){
      OCT_clear(&G1Octet);
      ECP_toOctet(&G1Octet,&ct[j],true);
      memcpy(combinedCharArray+current_pos,G1Octet.val,G1Octet.len);
      current_pos += G1Octet.len;

    }
  memcpy(combinedCharArray+current_pos,policy,policy_len);
      current_pos += policy_len;
    
Serial.print("packet assembly:");  stop(start_time);Serial.print(",");

start_time=start(); 
schnorr.sign((const unsigned char*)combinedCharArray + 22, totalLength-86, mynonce,(unsigned char*) combinedCharArray+62+514+arraySize*33+5+policy_len,(unsigned char*)combinedCharArray+62+514+arraySize*33+5+policy_len+32, public_point);
 Serial.print("schnorr:");stop(start_time);Serial.print(",");  
 
start_time=start(); 
  combinedCharArray[totalLength] = '\0';
esp_wifi_80211_tx(WIFI_IF_AP, combinedCharArray, sizeof(combinedCharArray), false);
 Serial.print("wifi txn:");stop(start_time);Serial.print(","); 
 
//  for (int i = 0; i < totalLength; i++) {
//    if (combinedCharArray[i] < 16) {
//        Serial.print("0");
//    }
//    Serial.print(combinedCharArray[i], HEX);
////    Serial.print(" ");
//}
//Serial.println("");
Serial.print("Total time:");stop(total_time);Serial.println("");

    
  }
}
void loop() {
  // put your main code here, to run repeatedly:

}
