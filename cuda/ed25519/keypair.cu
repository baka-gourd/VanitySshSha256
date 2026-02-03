#include "ed25519.h"
#include "sha512.h"
#include "ge.h"


__device__ void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;

    // First 32 bytes: Hash and clamp the seed as the scalar for signing
    sha512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    // Derive public key from private scalar
    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
    
    // Second 32 bytes: Copy the public key to form the complete 64-byte private key
    // This is what Solana wallets like Phantom expect for private key import
    for (int i = 0; i < 32; i++) {
        private_key[32+i] = public_key[i];
    }
}
