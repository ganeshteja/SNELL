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
unsigned char private_key[48] = {0x9f, 0x33, 0xb2, 0xc9, 0x54, 0x45, 0x05, 0x14, 0x0d, 0xae, 0x11, 0xcc, 0x40, 0x75, 0x9c, 0x32, 0x3f, 0x4a, 0xf0, 0x67, 0xf1, 0x0f, 0x5d, 0xd7, 0xd9, 0xea, 0x91, 0x09, 0xa0, 0x9f, 0xc1, 0xf5, 0x03, 0x2d, 0xb5, 0x23, 0xd4, 0xa9, 0x30, 0xda, 0x46, 0xab, 0x80, 0xe6, 0xb9, 0x94, 0xe7, 0x57};

// Public key
unsigned char public_key1[97] = {0x04, 0xe8, 0x9c, 0x30, 0xfb, 0x28, 0xc3, 0x52, 0xb1, 0x9d, 0x1d, 0xcd, 0x2e, 0xc6, 0xf2, 0xac, 0xdf, 0xaa, 0x25, 0xe1, 0x45, 0x37, 0xdb, 0x9f, 0x35, 0x5b, 0x5a, 0xc4, 0x5e, 0x51, 0x58, 0x03, 0x18, 0x31, 0x52, 0x6a, 0x32, 0xd2, 0xb3, 0xb5, 0x3d, 0xad, 0x0e, 0xf9, 0x16, 0xa9, 0x55, 0x7e, 0xf6, 0x5b, 0xef, 0x2c, 0x73, 0xab, 0x39, 0x9e, 0xd1, 0x99, 0xb4, 0x9d, 0xcf, 0x85, 0x73, 0x25, 0x60, 0xd8, 0xd3, 0xd4, 0x74, 0xb8, 0x06, 0x7a, 0x4f, 0x0c, 0x7f, 0xe7, 0x65, 0xef, 0x65, 0x50, 0x5c, 0xd8, 0xc4, 0xba, 0x4e, 0x45, 0x05, 0xef, 0xa8, 0xf0, 0x1e, 0x6f, 0xe4, 0x4e, 0x1f, 0xc1, 0x19};




unsigned char mynonce[NONCE_SIZE] = {0};
  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned char public_point[96];
  unsigned char verQ[96];
  unsigned char R[32];
  unsigned char s[48];
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
//    Serial.print("Qs:");
//    print_hex(public_point,96);
//    Serial.print("s:");
//    print_hex(s,48);
//     Serial.print("R:");
//    print_hex(R,32);
//    Serial.println("");

  }

digitalWrite(2,HIGH);


}

void loop() {
  // put your main code here, to run repeatedly:


//  long int t1 = millis();
//  schnorr_sign((const unsigned char*) message,strlen(message));
//  long int t2 = millis();
////  Serial.print("Time taken by the task: ");
//  Serial.println(t2-t1);
////  Serial.println(" milliseconds");
////  Serial.print("n:");
////  print_hex(mynonce,32);
////
////  Serial.print("Q:");
////  print_hex(public_point,96);
////  Serial.print("s:");
////  print_hex(s,48);
////   Serial.print("R:");
////  print_hex(R,32);
////  Serial.println("");
//// 
  
  
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
    mbedtls_ecp_group secp384r1;
    mbedtls_ecp_group_init(&secp384r1);
    mbedtls_ecp_group_load(&secp384r1, MBEDTLS_ECP_DP_SECP384R1);

    // Initialize point and MPI
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&k);

    // Load nonce into MPI
    mbedtls_mpi_read_binary(&k, nonce, 32);

    // Compute public nonce point
    mbedtls_ecp_mul(&secp384r1, &Q, &k, &secp384r1.G, NULL, NULL);

    // Write public nonce point to buffer
    mbedtls_mpi_write_binary(&Q.X, public_point, 48);
    mbedtls_mpi_write_binary(&Q.Y, public_point+ 48, 48);

    //compute the digest of Q||m (Qx || Qy || m)
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, public_point, 96);
    mbedtls_sha256_update(&sha256_ctx, message, strlen((const char*) message));
    mbedtls_sha256_finish(&sha256_ctx, challenge);

    // Free resources
    mbedtls_mpi_free(&k);
    mbedtls_ecp_point_free(&Q);
    mbedtls_sha256_free(&sha256_ctx);
    mbedtls_ecp_group_free(&secp384r1);
   

}

void compute_signature_scalar(const unsigned char* nonce, const unsigned char* message_digest, const unsigned char* private_key, unsigned char* signature_scalar)
{
    mbedtls_mpi k, e, x, s;
    mbedtls_ecp_group secp384r1;

    // Initialize group and MPIs
    mbedtls_ecp_group_init(&secp384r1);
    mbedtls_ecp_group_load(&secp384r1, MBEDTLS_ECP_DP_SECP384R1);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&s);

    // Load inputs into MPIs
    mbedtls_mpi_read_binary(&k, nonce, 32);
    mbedtls_mpi_read_binary(&e, message_digest, 32);
    mbedtls_mpi_read_binary(&x, private_key, 48);

    // Compute s = k + e*x mod n
    mbedtls_mpi_mul_mpi(&s, &e, &x);
    mbedtls_mpi_add_mpi(&s, &s, &k);
    mbedtls_mpi_mod_mpi(&s, &s, &secp384r1.N);

    // Write signature scalar to buffer
    mbedtls_mpi_write_binary(&s, signature_scalar, 48);

    // Free resources
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&k);
    mbedtls_ecp_group_free(&secp384r1);

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
  mbedtls_ecp_group secp384r1;
  mbedtls_ecp_group_init(&secp384r1);
  mbedtls_ecp_group_load(&secp384r1, MBEDTLS_ECP_DP_SECP384R1);
  

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
  mbedtls_mpi_read_binary(&s, signature_scalar, 48);
  mbedtls_mpi_read_binary(&r, challenge, 32);
  mbedtls_ecp_point_read_binary(&secp384r1, &A, public_key1, sizeof(public_key1));
  mbedtls_mpi_lset(&one, 1);
  mbedtls_mpi_lset(&neg, -1);
  
  //Calculate sG =s*G; rA = r*A; Q = 1*sG + (-1)*rA
  mbedtls_ecp_mul(&secp384r1, &sG, &s, &secp384r1.G, NULL, NULL);
  mbedtls_ecp_mul(&secp384r1,&rA,&r,&A,NULL, NULL);
  mbedtls_ecp_muladd(&secp384r1, &Q, &one,&sG,&neg,&rA);

  if ( mbedtls_ecp_is_zero( &Q ) ) {
          Serial.println("invalid signature");
    } 
  mbedtls_mpi_write_binary(&Q.X, verp, 48);
  mbedtls_mpi_write_binary(&Q.Y, verp+ 48, 48);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_point_free(&A);
  mbedtls_ecp_point_free(&rA);
  mbedtls_ecp_point_free(&sG);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);

  mbedtls_mpi_free(&one);
  mbedtls_mpi_free(&neg);
  mbedtls_ecp_group_free(&secp384r1);
//  Serial.print("Qv:");
//  print_hex(verp,96);        
    // Compute v = H(Q||m)
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, verp, 96);
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
