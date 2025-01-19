#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
// Values H0[0] - H[3] were taken from the MD5 algorithm, H[4] was extended from those values
uint32_t H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};


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
 * Rotates the bits in a word w n bits to the left
 * @param w word to rotate
 * @param n number of bits to rotate left
 * @returns the resulting rotated value
 */
uint32_t rotl(uint32_t w, int n) {
    return (w << n) | (w >> (32 - n));
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


/**********************
*** CORE SHA-1 HASH ***
**********************/
/**
 * Performs the core compression function of SHA-1
 * @param block the 512-bit block of the message that is being worked on
 * @param prev_H (IN/OUT) the outputted hash message from the previous call to this function (or the initial hash). Will contain the resulting hash upon return
 */
void compress(uint8_t* block, uint32_t *prev_H) {
    /*** Create the 80-entry message schedule ***/
    uint32_t *W = calloc(80, sizeof(uint32_t));

    // The first 16 words are set to the current block
    // Have to do extra work since SHA works in BIG ENDIAN, but this implementation is in LITTLE ENDIAN
    for (int i = 0; i < 16; i++) {
        W[i] = (block[4*i] << 24) | (block[4*i + 1] << 16) | (block[4*i + 2] << 8) | (block[4*i + 3]);
    }

    // The remainder of the message schedule is derived from the words within the block
    for (int i = 16; i < 80; i++) {
        W[i] = rotl(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    /*** Perform the compression iteration 80 times ***/
    // Initialize the states
    uint32_t A = prev_H[0];
    uint32_t B = prev_H[1];
    uint32_t C = prev_H[2];
    uint32_t D = prev_H[3];
    uint32_t E = prev_H[4];

    // Perform the iteration function
    for (int i = 0; i < 80; i++) {
        // Get the values for F and k
        // Values for k were chosen by doing 2^30 times the square roots of 2, 3, 5, and 10, rounded to the nearest integer
        uint32_t F = 0;
        uint32_t k = 0;
        if (i < 20) {
            F = ch(B, C, D);
            k = 0x5A827999;
        }
        else if (i < 40) {
            F = B ^ C ^ D;
            k = 0x6ED9EBA1;
        }
        else if (i < 60) {
            F = maj(B, C, D);
            k = 0x8F1BBCDC;
        }
        else {
            F = B ^ C ^ D;
            k = 0xCA62C1D6;
        }

        uint32_t temp = rotl(A, 5) + F + E + k + W[i];
        E = D;
        D = C;
        C = rotl(B, 30);
        B = A;
        A = temp;
    }

    // Add the results to the previous hash to get the NEW hash
    prev_H[0] += A; 
    prev_H[1] += B; 
    prev_H[2] += C; 
    prev_H[3] += D; 
    prev_H[4] += E; 
}

/**
 * Performs the SHA-1 hash function
 * @param msg the message to calculate the hash of
 * @returns the digest of the msg
 */
uint8_t* sha1(uint8_t *msg) {
    /*** PREPROCESSING ***/
    // Pad the message
    uint8_t *padded = NULL;
    int padded_len = 0;
    pad_msg(msg, strlen(msg), &padded, &padded_len);
    // Breaking the padded message into blocks will be done in the main loop

    /*** CORE HASH FUNCTIONALITY ***/
    uint32_t H[5] = {0}; // The most recent hash value
    memcpy(H, H0, 160/8); // Set the initial hash value to the constant H0

    // Perform the compression function for each block in the message
    for (int block_index = 0; block_index < (padded_len / 64); block_index++) {
        uint8_t* block = &padded[block_index * 64];
        compress(block, H);
    }

    // Convert the BIG ENDIAN final hash back into LITTLE ENDIAN for this implementation
    // (Also converts the word-index hash back into byte-index)
    uint8_t *digest = malloc(160/8);
    for (int i = 0; i < 160/8; i++) {
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
    uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
    printf("message = %s\n", msg);

    uint8_t *digest = sha1(msg);
    printf("digest = %s\n", digest);
    printf("       = ");
    for (int i = 0; i < 160/8; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free(digest);
    return 0;
}