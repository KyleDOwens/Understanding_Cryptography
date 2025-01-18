#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
#define HASHSIZE = 256

// Derived from the fractional parts of the cube roots of the first 64 prime numbers to show there is no backdoor
uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Derived from the fractional parts of the square roots of the first 8 prime numbers to show there is no backdoor
uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};


/********************
*** PREPROCESSING ***
********************/
/**
 * Pad the message to be a multiple of the 512 bits
 * Will append a 1, then k zero bits, and then a 64-bit block at the end containing the original msg length
 * @param msg the original message to pad
 * @param len the length of msg in BYTES
 * @param padded (OUTPUT) a double pointer where the outputted padded message will be but
 * @param len_padded (OUTPUT) the length of the padded message in BYTES
 */
void pad_msg(uint8_t *msg, int len, uint8_t **padded, int *len_padded) {
    // The number of 0s needed, k, is given by: k = (512 - 64 - len - 1) = 448 - (len + 1) mod 512
    int k = (448 - 8*len) % 512;
    if (k < 0) {
        k += 512;
    }

    // Will append a 1, then k zero bits, and then a 64-bit block at the end containing the original msg length
    // Add an extra bit to k for the leading 1 bit, and then convert # bits to # bytes
    *len_padded = len + (k+1)/8 + 64/8;
    *padded = malloc(*len_padded);

    memcpy(*padded, msg, len); // Copy over the original message
    memset(*padded + len, 0, (*len_padded - len)); // Set all padded bits to 0
    (*padded)[len] = 0x80; // Set the most significant padded bit to 1

    // Set the last 64 bits as the 64-bit representation of the original msg length (IN BITS)
    // This implementation uses LITTLE ENDIAN, so must convert to BIG ENDIAN for SHA-2 algorithm
    uint64_t len64 = (uint64_t)(len * 8);
    for (int i = 0; i < 8; i++) {
        (*padded)[*len_padded - 1 - i] = len64 >> 8*i;
    }
}


/**************************
*** COMPRESSION HELPERS ***
**************************/
/**
 * Rotates the bits in a word w n bits to the right
 * @param w word to rotate
 * @param n number of bits to rotate right
 * @returns the resulting rotated value
 */
uint32_t rotr(uint32_t w, int n) {
    return (w >> n) | (w << (32 - n));
}

/**
 * Shifts the bits in a word w n bits to the right
 * @param w word to shift
 * @param n number of bits to shift right
 * @returns the resulting shifted value
 */
uint32_t shr(uint32_t w, int n) {
    return (w >> n);
}

/**
 * Performs the sigma_0 function on a word
 * @param w word to perform the sigma_0 function on
 * @returns the result of the sigma_0 function
 */
uint32_t sig0(uint32_t w) {
    return rotr(w, 7) ^ rotr(w, 18) ^ shr(w, 3);
}

/**
 * Performs the sigma_1 function on a word
 * @param w word to perform the sigma_1 function on
 * @returns the result of the sigma_1 function
 */
uint32_t sig1(uint32_t w) {
    return rotr(w, 17) ^ rotr(w, 19) ^ shr(w, 10);
}

/**
 * Performs the SIGMA_0 (capitalized) function on a word
 * @param w word to perform the SIGMA_0 function on
 * @returns the result of the SIGMA_0 function
 */
uint32_t SIG0(uint32_t w) {
    return rotr(w, 2) ^ rotr(w, 13) ^ rotr(w, 22);
}

/**
 * Performs the SIGMA_1 (capitalized) function on a word
 * @param w word to perform the SIGMA_1 function on
 * @returns the result of the SIGMA_1 function
 */
uint32_t SIG1(uint32_t w) {
    return rotr(w, 6) ^ rotr(w, 11) ^ rotr(w, 25);
}

/**
 * Performs the Choice function, which chooses the respective bit of y or z, based on the corresponding bit of x
 * @param x the value whose bit will determine which other inpput y or z will be chosen from
 * @param y the input to choose from when x's bit = 0
 * @param z the input to choose from when x's bit = 1
 * @returns the result of the choosing
 */
uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

/**
 * Performs the Majority function, which chooses the output bit is what value had the majority among x, y, and z
 * @param x the first input
 * @param y the second input
 * @param z the third input
 * @returns the result of the majority bits within x, y, and z
 */
uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}


/************************
*** CORE SHA-256 HASH ***
************************/
/**
 * Performs the core compression function of SHA-256
 * @param block the 512-bit block of the message that is being worked on
 * @param prev_H (IN/OUT) the outputted hash message from the previous call to this function (or the initial hash). Will contain the resulting hash upon return
 */
void compress(uint8_t* block, uint32_t *prev_H) {
    /*** Create the 64-entry message schedule ***/
    uint32_t *W = calloc(64, sizeof(uint32_t));

    // The first 16 words are set to the current block
    // Have to do extra work since SHA works in BIG ENDIAN, but this implementation is in LITTLE ENDIAN
    for (int i = 0; i < 16; i++) {
        W[i] = (block[4*i] << 24) | (block[4*i + 1] << 16) | (block[4*i + 2] << 8) | (block[4*i + 3]);
    }

    // The remainder of the message schedule is derived from the words within the block
    for (int i = 16; i < 64; i++) {
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
    }

    /*** Perform the compression iteration 64 times ***/
    // Initialize the states
    uint32_t A = prev_H[0];
    uint32_t B = prev_H[1];
    uint32_t C = prev_H[2];
    uint32_t D = prev_H[3];
    uint32_t E = prev_H[4];
    uint32_t F = prev_H[5];
    uint32_t G = prev_H[6];
    uint32_t H = prev_H[7];

    // Perform the iteration function
    for (int i = 0; i < 64; i++) {
        uint32_t temp1 = H + SIG1(E) + ch(E, F, G) + k[i] + W[i];
        uint32_t temp2 = SIG0(A) + maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    // Add the results to the previous hash to get the NEW hash
    prev_H[0] += A; 
    prev_H[1] += B; 
    prev_H[2] += C; 
    prev_H[3] += D; 
    prev_H[4] += E; 
    prev_H[5] += F; 
    prev_H[6] += G; 
    prev_H[7] += H; 
}

/**
 * Performs the SHA-256 hash function
 * @param msg the message to calculate the hash of
 * @returns the digest of the msg
 */
uint8_t* sha256(uint8_t *msg) {
    /*** PREPROCESSING ***/
    // Pad the message
    uint8_t *padded = NULL;
    int padded_len = 0;
    pad_msg(msg, strlen(msg), &padded, &padded_len);
    // Breaking the padded message into blocks will be done in the main loop

    /*** CORE HASH FUNCTIONALITY ***/
    uint32_t H[8] = {0}; // The most recent hash value
    memcpy(H, H0, 256/8); // Set the initial hash value to the constant H0

    // Perform the compression function for each block in the message
    for (int block_index = 0; block_index < (padded_len / 64); block_index++) {
        uint8_t* block = &padded[block_index * 64];
        compress(block, H);
    }

    // Convert the BIG ENDIAN final hash back into LITTLE ENDIAN for this implementation
    // (Also converts the word-index hash back into byte-index)
    uint8_t *digest = malloc(256/8);
    for (int i = 0; i < 32; i++) {
        digest[i] = (H[i/4] >> (24 - 8*i)) & 0x000000FF;
    }

    free(padded);
    return digest;
}


/**************
*** TESTING ***
**************/
int main() {    
    // Set test variables for the cipher
    uint8_t msg[] = "sha-256 test msg!";
    printf("message = %s\n", msg);

    uint8_t *digest = sha256(msg);
    printf("digest = %s\n", digest);
    printf("       = ");
    for (int i = 0; i < 256/8; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free(digest);
    return 0;
}
