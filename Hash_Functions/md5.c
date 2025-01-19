#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
// Derived from: k[i] = floor(2^32 * abs(sin(i + 1)))
uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// s[i] represents the shift amount for round i
uint32_t s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// Initial hash values in LITTLE ENDIAN, are just the values counting up and down in base-16 (01 23 45 67 etc.)
uint32_t H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};


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
    uint64_t len64 = (uint64_t)(len * 8);
    for (int i = 0; i < 8; i++) {
        (*padded)[*len_padded - 1 - i] = len64 >> (56 - 8*i);
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
*** CORE MD5 HASH ***
**********************/
/**
 * Performs the core compression function of MD5
 * @param block the 512-bit block of the message that is being worked on
 * @param prev_H (IN/OUT) the outputted hash message from the previous call to this function (or the initial hash). Will contain the resulting hash upon return
 */
void compress(uint8_t* block, uint32_t *prev_H) {
    /*** Create the 16-entry message schedule ***/
    uint32_t *M = calloc(32, sizeof(uint32_t));
    memcpy(M, block, 512/8); // Can keep the LITTLE ENDIAN of the original message

    /*** Perform the compression iteration 80 times ***/
    // Initialize the states
    uint32_t A = prev_H[0];
    uint32_t B = prev_H[1];
    uint32_t C = prev_H[2];
    uint32_t D = prev_H[3];

    // Perform the iteration function
    for (int i = 0; i < 64; i++) {
        // Get the values for F and g
        uint32_t F = 0;
        uint32_t g = 0;
        if (i < 16) {
            F = ch(B, C, D);
            g = i;
        }
        else if (i < 32) {
            F = ch(D, B, C);
            g = (5*i + 1) % 16;
        }
        else if (i < 48) {
            F = B ^ C ^ D;
            g = (3*i + 5) % 16;
        }
        else {
            F = C ^ (B | (~D));
            g = (7*i) % 16;
        }

        uint32_t temp = D;
        D = C;
        C = B;
        B = B + rotl(A + F + k[i] + M[g], s[i]);
        A = temp;
    }

    // Add the results to the previous hash to get the NEW hash
    prev_H[0] += A; 
    prev_H[1] += B; 
    prev_H[2] += C; 
    prev_H[3] += D; 
}

/**
 * Performs the MD5 hash function
 * @param msg the message to calculate the hash of
 * @returns the digest of the msg
 */
uint8_t* md5(uint8_t *msg) {
    /*** PREPROCESSING ***/
    // Pad the message
    uint8_t *padded = NULL;
    int padded_len = 0;
    pad_msg(msg, strlen(msg), &padded, &padded_len);
    // Breaking the padded message into blocks will be done in the main loop

    for (int i = 0; i < 512/8; i++) {
        printf("%02x", padded[i]);
    }
    printf("\n");

    /*** CORE HASH FUNCTIONALITY ***/
    uint32_t H[4] = {0}; // The most recent hash value
    memcpy(H, H0, 128/8); // Set the initial hash value to the constant H0

    // Perform the compression function for each block in the message
    for (int block_index = 0; block_index < (padded_len / 64); block_index++) {
        uint8_t* block = &padded[block_index * 64];
        compress(block, H);
    }

    // Note that this output is in LITTLE ENDIAN already
    // (Also converts the word-index hash back into byte-index)
    uint8_t *digest = malloc(128/8);
    memcpy(digest, H, 128/8);

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

    uint8_t *digest = md5(msg);
    printf("digest = %s\n", digest);
    printf("       = ");
    for (int i = 0; i < 128/8; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free(digest);
    return 0;
}