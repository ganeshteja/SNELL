#include "mbedtls/aes.h"
#include <esp_system.h>
#define NONCE_SIZE 32 
#define MIN(a, b) ((a) < (b) ? (a) : (b))

char * key = "abcdefghijklmnopabcdefghijklmnop";

  



void generate_nonce(uint8_t *nonce) {
    int num_bytes_generated = 0;
    while (num_bytes_generated < NONCE_SIZE/2) {
        uint32_t random_num = esp_random();
        int num_bytes_to_copy = MIN(NONCE_SIZE - num_bytes_generated, sizeof(random_num));
        memcpy(nonce + num_bytes_generated, &random_num, num_bytes_to_copy);
        num_bytes_generated += num_bytes_to_copy;
    }
} 




void encrypt_ecb(char * plainText, char * key, unsigned char * outputBuffer){
 
  mbedtls_aes_context aes;
 
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, strlen(key) * 8 );
  mbedtls_aes_crypt_ecb( &aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plainText, outputBuffer);
  mbedtls_aes_free( &aes );
}

void encrypt_cbc(char * plainText, char * key, unsigned char * outputBuffer){
 
  mbedtls_aes_context aes;
  unsigned char iv[NONCE_SIZE/2] = {0};
  generate_nonce(iv);
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, strlen(key) * 8 );
  mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT,strlen(plainText),iv, (const unsigned char*)plainText, outputBuffer);
  mbedtls_aes_free( &aes );
}
 
void decrypt(unsigned char * chipherText, char * key, unsigned char * outputBuffer){
 
  mbedtls_aes_context aes;
 
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_dec( &aes, (const unsigned char*) key, strlen(key) * 8 );
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char*)chipherText, outputBuffer);
  mbedtls_aes_free( &aes );
}
 
void setup() {
 
  Serial.begin(115200);

}
 
void loop() {
unsigned char plainText[16] = {0}; 
unsigned char cipherTextOutput[16];
unsigned char decipheredTextOutput[16];

generate_nonce(plainText);
Serial.print("plainText:");
print_hex(plainText,16);


 long int t1 = millis();
  encrypt_ecb((char*)plainText, key, cipherTextOutput);
  long int t2 = millis();
  Serial.print("Time taken by the task enc: ");Serial.println(t2-t1);Serial.println(" milliseconds");

 Serial.println("Ciphered text:");
  for (int i = 0; i < 16; i++) {
 
    char str[3];
 
    sprintf(str, "%02x", (int)cipherTextOutput[i]);
    Serial.print(str);
  }
    decrypt(cipherTextOutput, key, decipheredTextOutput);
    Serial.print("\nDeciphered text:");
//  for (int i = 0; i < 16; i++) {
//    Serial.print((char)decipheredTextOutput[i]);
//  }
print_hex(decipheredTextOutput,16);
}


void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) {
            Serial.print("0");
        }
        Serial.print(data[i], HEX);
    }
    Serial.println();
}
