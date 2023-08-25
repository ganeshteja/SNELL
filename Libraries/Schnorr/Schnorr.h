#ifndef Schnorr_h
#define Schnorr_h
#include<Arduino.h>
#include <esp_system.h>
#include <mbedtls/sha256.h>
#include <mbedtls/platform.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>


#define NONCE_SIZE 32  // 256 bits
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define SHA256_DIGEST_LENGTH 32

class Schnorr {
public:
    Schnorr();
    void sign(const unsigned char* message,size_t message_len,unsigned char* nonce,unsigned char* myR,unsigned char* mys,unsigned char* public_point);
    void verify( const unsigned char* message, unsigned char* challenge, unsigned char* signature_scalar, unsigned char* verp);
    void print_hex(const unsigned char* data, size_t len);

private:
	
    void generate_nonce(uint8_t *nonce);
    void schnorr_challenge(const unsigned char* nonce, const unsigned char* message, unsigned char* challenge,unsigned char* public_point);
    void compute_signature_scalar(const unsigned char* nonce, const unsigned char* message_digest, const unsigned char* private_key, unsigned char* signature_scalar);
};

#endif
