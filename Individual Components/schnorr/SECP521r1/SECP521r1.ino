//#include <mbedtls/config.h>
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

// Private key
unsigned char private_key[66] = {0x00, 0xb7, 0x06, 0xf1, 0x6a, 0x24, 0x38, 0xe7, 0x80, 0x4f, 0xdd, 0xd1, 0x8c, 0x6e, 0x4b, 0x8d, 0xb8, 0xe4, 0x2d, 0x55, 0xdf, 0x83, 0xcd, 0x06, 0x81, 0xa0, 0xab, 0x68, 0x18, 0x1a, 0xc4, 0xa5, 0x38, 0x6c, 0x06, 0x0e, 0x2f, 0xd4, 0x0a, 0x8b, 0x13, 0x36, 0x15, 0xb2, 0x72, 0x58, 0x7a, 0x1b, 0xcf, 0x10, 0xda, 0x6b, 0x4e, 0xd1, 0x4d, 0x3d, 0xd6, 0xc1, 0xf8, 0x81, 0x50, 0x4d, 0x27, 0xd4, 0xf4, 0xcb};

// Public key
unsigned char public_key1[133] = {0x04, 0x00, 0xdc, 0x85, 0x3d, 0x22, 0xfb, 0x1b, 0x19, 0x25, 0x3f, 0x55, 0x50, 0x1f, 0x61, 0xd9, 0x9e, 0x38, 0x0d, 0xbc, 0x63, 0x1b, 0xb2, 0x2d, 0xe7, 0xdf, 0x10, 0xb4, 0x18, 0x84, 0x40, 0x88, 0x0a, 0xcc, 0xe4, 0xdd, 0x8e, 0xb6, 0x54, 0x67, 0x2c, 0x84, 0x3b, 0x34, 0x1d, 0x48, 0x8d, 0xde, 0x99, 0x89, 0xa6, 0x1f, 0x4e, 0xe2, 0x0d, 0x1f, 0xa6, 0xfb, 0x7a, 0x79, 0xcd, 0xdd, 0xbe, 0xa6, 0xd9, 0x1f, 0x31, 0x01, 0xed, 0x38, 0xe4, 0xd4, 0xe0, 0xe0, 0xb6, 0x50, 0x46, 0xba, 0x5a, 0x03, 0x19, 0xa4, 0xf0, 0x7e, 0xe2, 0xe7, 0xee, 0xa4, 0x25, 0xa9, 0x16, 0xbd, 0xc2, 0x29, 0xca, 0x6e, 0xa0, 0x52, 0xf8, 0xf5, 0xba, 0x17, 0x67, 0x89, 0x1d, 0x50, 0x03, 0x4b, 0x9a, 0x5c, 0xc3, 0xbd, 0xfe, 0xcf, 0xd1, 0xe3, 0xda, 0x05, 0x41, 0x12, 0x4f, 0x14, 0x11, 0x02, 0x83, 0xc4, 0x06, 0x5f, 0xec, 0x32, 0x7e, 0x77, 0xc7};




unsigned char mynonce[NONCE_SIZE] = {0};
  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned char public_point[132];
  unsigned char verQ[132];
  unsigned char R[32];
  unsigned char s[66];
  char message[] = "testing the message";

void setup() {
  // put your setup code here, to run once:

  
  Serial.begin(115200);
  while(!Serial); // Wait for serial connection

  pinMode (2, OUTPUT);
  digitalWrite(2,LOW);

  for(int i=0;i<100;i++){
    Serial.print(i);Serial.print(",");
    schnorr_sign((const unsigned char*) message,strlen(message));
    schnorr_verify((const unsigned char*) message,R,s,public_key1,verQ);
//    
//  //  Serial.print("Time taken by the task: ");
//    Serial.print(t2-t1);Serial.print(" milliseconds,");
//    Serial.print("n:");
//    print_hex(mynonce,32);
//  
//    Serial.print("Q:");
//    print_hex(public_point,132);
//    Serial.print("s:");
//    print_hex(s,66);
//     Serial.print("R:");
//    print_hex(R,32);
//    Serial.println("");
  }

}

void loop() {
  // put your main code here, to run repeatedly:


  
 
  
  
}

void generate_nonce(uint8_t *nonce) {
    int num_bytes_generated = 0;
    while (num_bytes_generated < NONCE_SIZE) {
        uint32_t random_num = esp_random();
        int num_bytes_to_copy = MIN(NONCE_SIZE - num_bytes_generated, sizeof(random_num));
        memcpy(nonce + num_bytes_generated, &random_num, num_bytes_to_copy);
        num_bytes_generated += num_bytes_to_copy;
    }
} 



void schnorr_challenge(const unsigned char* nonce, const unsigned char* message, unsigned char* challenge) {

  
    mbedtls_ecp_point Q;
    mbedtls_mpi k;

    // Initialize SHA-256 context
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
   
    // Initialize group
    mbedtls_ecp_group secp521r1;
    mbedtls_ecp_group_init(&secp521r1);
    mbedtls_ecp_group_load(&secp521r1, MBEDTLS_ECP_DP_SECP521R1);

    // Initialize point and MPI
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&k);

    // Load nonce into MPI
    mbedtls_mpi_read_binary(&k, nonce, 32);

    // Compute public nonce point
    mbedtls_ecp_mul(&secp521r1, &Q, &k, &secp521r1.G, NULL, NULL);

    // Write public nonce point to buffer
    mbedtls_mpi_write_binary(&Q.X, public_point, 66);
    mbedtls_mpi_write_binary(&Q.Y, public_point+ 66, 66);

    //compute the digest of Q||m (Qx || Qy || m)
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, public_point, 132);
    mbedtls_sha256_update(&sha256_ctx, message, strlen((const char*) message));
    mbedtls_sha256_finish(&sha256_ctx, challenge);

    // Free resources
    mbedtls_mpi_free(&k);
    mbedtls_ecp_point_free(&Q);
    mbedtls_sha256_free(&sha256_ctx);
    mbedtls_ecp_group_free(&secp521r1);
   

}

void compute_signature_scalar(const unsigned char* nonce, const unsigned char* message_digest, const unsigned char* private_key, unsigned char* signature_scalar)
{
    mbedtls_mpi k, e, x, s;
    mbedtls_ecp_group secp521r1;

    // Initialize group and MPIs
    mbedtls_ecp_group_init(&secp521r1);
    mbedtls_ecp_group_load(&secp521r1, MBEDTLS_ECP_DP_SECP521R1);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&s);

    // Load inputs into MPIs
    mbedtls_mpi_read_binary(&k, nonce, 32);
    mbedtls_mpi_read_binary(&e, message_digest, 32);
    mbedtls_mpi_read_binary(&x, private_key, 66);

    // Compute s = k + e*x mod n
    mbedtls_mpi_mul_mpi(&s, &e, &x);
    mbedtls_mpi_add_mpi(&s, &s, &k);
    mbedtls_mpi_mod_mpi(&s, &s, &secp521r1.N);

    // Write signature scalar to buffer
    mbedtls_mpi_write_binary(&s, signature_scalar, 66);

    // Free resources
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&k);
    mbedtls_ecp_group_free(&secp521r1);

}


void schnorr_sign(const unsigned char* message,size_t message_len){
long int t1 = millis();
 generate_nonce(mynonce);
 schnorr_challenge(mynonce,message,R);
 compute_signature_scalar(mynonce,R,private_key,s);
long int t2 = millis();
Serial.print("sign:");Serial.print(t2-t1);Serial.print(",");

}


void schnorr_verify( const unsigned char* message, unsigned char* challenge, unsigned char* signature_scalar, unsigned char* public_key,unsigned char* verp){
 long int t1 = millis();
  mbedtls_ecp_point Q, A,sG,rA;
  mbedtls_mpi s, r,neg,one;
  unsigned char v[32];

 
  // Initialize group
  mbedtls_ecp_group secp521r1;
  mbedtls_ecp_group_init(&secp521r1);
  mbedtls_ecp_group_load(&secp521r1, MBEDTLS_ECP_DP_SECP521R1);
  

  // Initialize point and MPI
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_point_init(&A);
  mbedtls_ecp_point_init(&sG);
  mbedtls_ecp_point_init(&rA);
 
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&neg);
  mbedtls_mpi_init(&one);
  

  // Load nonce into MPI
  mbedtls_mpi_read_binary(&s, signature_scalar, 66);
  mbedtls_mpi_read_binary(&r, challenge, 32);
  mbedtls_ecp_point_read_binary(&secp521r1, &A, public_key1, sizeof(public_key1));
  mbedtls_mpi_lset(&one, 1);
  mbedtls_mpi_lset(&neg, -1);
  
  //Calculate sG =s*G; rA = r*A; Q = 1*sG + (-1)*rA
  mbedtls_ecp_mul(&secp521r1, &sG, &s, &secp521r1.G, NULL, NULL);
  mbedtls_ecp_mul(&secp521r1,&rA,&r,&A,NULL, NULL);
  mbedtls_ecp_muladd(&secp521r1, &Q, &one,&sG,&neg,&rA);

  if ( mbedtls_ecp_is_zero( &Q ) ) {
          Serial.println("invalid signature");
    } 
  mbedtls_mpi_write_binary(&Q.X, verp, 66);
  mbedtls_mpi_write_binary(&Q.Y, verp+ 66, 66);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_point_free(&A);
  mbedtls_ecp_point_free(&rA);
  mbedtls_ecp_point_free(&sG);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);

  mbedtls_mpi_free(&one);
  mbedtls_mpi_free(&neg);
  mbedtls_ecp_group_free(&secp521r1);
//  Serial.print("Qv:");
//  print_hex(verp,132);        
    // Compute v = H(Q||m)
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, verp, 132);
  mbedtls_sha256_update(&sha256_ctx, message, strlen((const char*) message));
  mbedtls_sha256_finish(&sha256_ctx, v);
  mbedtls_sha256_free(&sha256_ctx);
  long int t2 = millis();
  Serial.print("verify:");Serial.print(t2-t1);Serial.print(",");
//    Serial.print("v:");
//    print_hex(v,32);
    if(memcmp(v, challenge, 32) ==0){
      Serial.println("Message verified,");
    }
    else{Serial.println("invalid signature,");}
}



void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) {
            Serial.print("0");
        }
        Serial.print(data[i], HEX);
    }
    Serial.print(",");
}
