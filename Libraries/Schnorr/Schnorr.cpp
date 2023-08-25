#include "Schnorr.h"
// #include "keys.h"
Schnorr::Schnorr() {}

// Private key
unsigned char private_key[32] = {0xa3, 0xa6, 0x1a, 0x2d, 0xe0, 0x96, 0x8a, 0x5b, 0xac, 0x2c, 0xc9, 0xb6, 0x82, 0xbf, 0x54, 0x7b, 0xb9, 0x4c, 0x2d, 0xc6, 0x4d, 0x96, 0xa0, 0x57, 0x10, 0x95, 0x5d, 0x0f, 0x8a, 0x17, 0x11, 0x3a};

// Public key
unsigned char public_key1[65] = {0x04,0xb5, 0x2b, 0x53, 0x71, 0xdd, 0xe4, 0x42, 0x57, 0xe7, 0xff, 0xc6, 0x5e, 0xb5, 0x65, 0x61, 0xd3, 0x8d, 0x32, 0x96, 0x65, 0x60, 0xb5, 0xcf, 0xc6, 0x04, 0x8c, 0xb8, 0x0d, 0x29, 0x7d, 0x1e, 0xb1, 0x3b, 0x19, 0x03, 0xa0, 0xc4, 0xe9, 0xb3, 0xef, 0xea, 0x62, 0xf5, 0x94, 0x16, 0xfb, 0x82, 0x7f, 0x96, 0x79, 0x45, 0x55, 0x9a, 0x67, 0xd9, 0xf9, 0x17, 0x53, 0xf9, 0xfa, 0x9a, 0x24, 0xa8, 0xca};



void Schnorr::sign(const unsigned char* message,size_t message_len,unsigned char* nonce,unsigned char* myR,unsigned char* mys,unsigned char* public_point){
long int t1 = micros();
 int num_bytes_generated = 0;
  while (num_bytes_generated < NONCE_SIZE) {
      uint32_t random_num = esp_random();
      int num_bytes_to_copy = MIN(NONCE_SIZE - num_bytes_generated, sizeof(random_num));
      memcpy(nonce + num_bytes_generated, &random_num, num_bytes_to_copy);
      num_bytes_generated += num_bytes_to_copy;
  }
 schnorr_challenge(nonce,message,myR,public_point);
 compute_signature_scalar(nonce,myR,private_key,mys);
long int t2 = micros();
Serial.print("sign:");Serial.print(t2-t1);Serial.print(",");
}

void Schnorr::verify( const unsigned char* message, unsigned char* challenge, unsigned char* signature_scalar, unsigned char* verp){
 long int t1 = micros();
  mbedtls_ecp_point Q, A,sG,rA;
  mbedtls_mpi s, r,neg,one;
  unsigned char v[32];

 
  // Initialize group
  mbedtls_ecp_group secp256k1;
  mbedtls_ecp_group_init(&secp256k1);
  mbedtls_ecp_group_load(&secp256k1, MBEDTLS_ECP_DP_SECP256K1);
  

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
  mbedtls_mpi_read_binary(&s, signature_scalar, 32);
  mbedtls_mpi_read_binary(&r, challenge, 32);
  mbedtls_ecp_point_read_binary(&secp256k1, &A, public_key1, sizeof(public_key1));
  mbedtls_mpi_lset(&one, 1);
  mbedtls_mpi_lset(&neg, -1);
  
  //Calculate sG =s*G; rA = r*A; Q = 1*sG + (-1)*rA
  mbedtls_ecp_mul(&secp256k1, &sG, &s, &secp256k1.G, NULL, NULL);
  mbedtls_ecp_mul(&secp256k1,&rA,&r,&A,NULL, NULL);
  mbedtls_ecp_muladd(&secp256k1, &Q, &one,&sG,&neg,&rA);

  if ( mbedtls_ecp_is_zero( &Q ) ) {
          Serial.println("invalid signature");
    } 
  mbedtls_mpi_write_binary(&Q.X, verp, 32);
  mbedtls_mpi_write_binary(&Q.Y, verp+ 32, 32);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_point_free(&A);
  mbedtls_ecp_point_free(&rA);
  mbedtls_ecp_point_free(&sG);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);

  mbedtls_mpi_free(&one);
  mbedtls_mpi_free(&neg);
  mbedtls_ecp_group_free(&secp256k1);
          
    // Compute v = H(Q||m)
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, verp, 64);
  mbedtls_sha256_update(&sha256_ctx, message, strlen((const char*) message));
  mbedtls_sha256_finish(&sha256_ctx, v);
  mbedtls_sha256_free(&sha256_ctx);
  long int t2 = micros();
  // Serial.print("verify:");Serial.print(t2-t1);Serial.print(",");
  //  Serial.print("v:");
  //  print_hex(v,32);
    if(memcmp(v, challenge, 32) ==0){
      Serial.println("Message verified,");
    }
    else{Serial.println("invalid signature,");}
}

void Schnorr::print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) {
            Serial.print("0");
        }
        Serial.print(data[i], HEX);
    }
    Serial.println(",");
}


void Schnorr::generate_nonce(uint8_t *nonce) {
  int num_bytes_generated = 0;
  while (num_bytes_generated < NONCE_SIZE) {
      uint32_t random_num = esp_random();
      int num_bytes_to_copy = MIN(NONCE_SIZE - num_bytes_generated, sizeof(random_num));
      memcpy(nonce + num_bytes_generated, &random_num, num_bytes_to_copy);
      num_bytes_generated += num_bytes_to_copy;
  }
} 

void Schnorr::schnorr_challenge(const unsigned char* nonce, const unsigned char* message, unsigned char* challenge,unsigned char* public_point) {

  
    mbedtls_ecp_point Q;
    mbedtls_mpi k;

    // Initialize SHA-256 context
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
   
    // Initialize group
    mbedtls_ecp_group secp256k1;
    mbedtls_ecp_group_init(&secp256k1);
    mbedtls_ecp_group_load(&secp256k1, MBEDTLS_ECP_DP_SECP256K1);

    // Initialize point and MPI
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&k);

    // Load nonce into MPI
    mbedtls_mpi_read_binary(&k, nonce, 32);

    // Compute public nonce point
    mbedtls_ecp_mul(&secp256k1, &Q, &k, &secp256k1.G, NULL, NULL);

    // Write public nonce point to buffer
    mbedtls_mpi_write_binary(&Q.X, public_point, 32);
    mbedtls_mpi_write_binary(&Q.Y, public_point+ 32, 32);

    //compute the digest of Q||m (Qx || Qy || m)
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, public_point, 64);
    mbedtls_sha256_update(&sha256_ctx, message, strlen((const char*) message));
    mbedtls_sha256_finish(&sha256_ctx, challenge);

    // Free resources
    mbedtls_mpi_free(&k);
    mbedtls_ecp_point_free(&Q);
    mbedtls_sha256_free(&sha256_ctx);
    mbedtls_ecp_group_free(&secp256k1);
   

}

void Schnorr::compute_signature_scalar(const unsigned char* nonce, const unsigned char* message_digest, const unsigned char* private_key, unsigned char* signature_scalar)
{
    mbedtls_mpi k, e, x, s;
    mbedtls_ecp_group secp256k1;

    // Initialize group and MPIs
    mbedtls_ecp_group_init(&secp256k1);
    mbedtls_ecp_group_load(&secp256k1, MBEDTLS_ECP_DP_SECP256K1);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&s);

    // Load inputs into MPIs
    mbedtls_mpi_read_binary(&k, nonce, 32);
    mbedtls_mpi_read_binary(&e, message_digest, 32);
    mbedtls_mpi_read_binary(&x, private_key, 32);

    // Compute s = k + e*x mod n
    mbedtls_mpi_mul_mpi(&s, &e, &x);
    mbedtls_mpi_add_mpi(&s, &s, &k);
    mbedtls_mpi_mod_mpi(&s, &s, &secp256k1.N);

    // Write signature scalar to buffer
    mbedtls_mpi_write_binary(&s, signature_scalar, 32);

    // Free resources
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&k);
    mbedtls_ecp_group_free(&secp256k1);

}

