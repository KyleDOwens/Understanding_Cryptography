#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
#define KEYSIZE 80 // 80 or 128

uint8_t sbox[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
uint8_t inv_sbox[16] = {0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

// P[i] = (i*16) mod 63, except for P[63] = 63
uint8_t perm[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};


/***********************
*** HELPER FUNCTIONS ***
***********************/
void print_block(uint64_t block) {
    for (int i = 63; i >= 0; i--) {
        printf("%ld", (block >> i) & 0x0000000000000001);
    }
    printf("\n\r");
}

void print_halfblock(uint32_t halfblock) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (halfblock >> i) & 0x0000000000000001);
    }
    printf("\n\r");
}

void print_byte(uint8_t byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 0x01);
    }
    printf("\n\r");
}


/*******************
*** KEY SCHEDULE ***
*******************/
/**
 * Obtains the leftmost 64 bits from the key. Works for 80-bit and 128-bit keys
 * @param key pointer to the key to obtain the 64 bits from
 * @returns uint64_t representing the leftmost 64 bits
 */
uint64_t leftmost64(uint8_t *key) {
    uint64_t output = 0;
    for (int i = 0; i < 64/8; i++) {
        output <<= 8;
        output |= key[KEYSIZE/8 - i];
    }
    return output;
}

/**
 * Rotates all values in the key left by 1. Works for 80-bit and 128-bit keys
 * @param key pointer to the key to rotate
 */
void rotate_left(uint8_t *key) {
    // Store first bit for wrap-around
    uint8_t carry = (key[KEYSIZE/8 - 1] >> 7) & 0x01;

    // Rotate all bytes except first
    for (int i = KEYSIZE/8 - 1; i > 0; i--) {
        key[i] = (key[i] << 1) | ((key[i-1] >> 7) & 0x01);
    }
    
    // Rotate first byte with the wrap-around carry
    key[0] = (key[0] << 1) | carry;
}

/**
 * Generates all 32 round keys (subkeys) for the PRESENT cipher
 * @param key the 80-bit or 128-bit main key
 * @returns pointer to the array of 32 64-bit subkeys
 */
uint64_t* generate_round_keys(uint8_t *key) {
    /*** 80-bit KEY FUNCTION ***/
    // Step 1: [k79,k78,...,k1,k0] = [k18,k17,...,k20,k19]
    // Step 2: [k79,k78,k77,k76] = S[k79,k78,k77,k76]
    // Step 3: [k19,k18,k17,k16,k15] = [k19,k18,k17,k16,k15] XOR round_counter
    // subkey[round_counter] = leftmost 64 bits
    
    /*** 128-bit KEY FUNCTION ***/
    // Step 1: [k127,k126,...,k1,k0] = [k66,k65,...,k68,k67]
    // Step 2: [k127,k126,k125,k124] = S[k127,k126,k125,k124]
    // Step 3: [k123,k122,k121,k120] = S[k123,k122,k121,k120]
    // Step 4: [k66,k65,k64,k63,k62] = [k66,k65,k64,k63,k62] XOR round_counter
    // subkey[round_counter] = leftmost 64 bits

    uint64_t* subkeys = (uint64_t*)calloc(32, sizeof(uint64_t));

    // Get the first subkey
    subkeys[0] = leftmost64(key); // Round key 1

    for (uint8_t round_counter = 2; round_counter <= 32; round_counter++) {
        // Step 1: rotate key left by 61
        for (int i = 0; i < 61; i++) {
            rotate_left(key);
        }

        // Step 2: set 4 leftmost bits to s-box values for 80-bit key, or 8 leftmost bits for 128-bit key
        uint8_t msb_nibble = key[KEYSIZE/8 -1] >> 4; // Get the MSB nibble as input to the s-box
        key[KEYSIZE/8 -1] &= 0x0F; // Set the nibble to 0
        key[KEYSIZE/8 -1] |= sbox[msb_nibble] << 4; // Set MSB nibble to the s-box value

        if (KEYSIZE == 128) {
            uint8_t msb_nibble = key[KEYSIZE/8 -1] & 0x0F; // Get the 2nd MSB nibble as input to the s-box
            key[KEYSIZE/8 -1] &= 0xF0; // Set the nibble to 0
            key[KEYSIZE/8 -1] |= sbox[msb_nibble]; // Set 2nd MSB nibble to the s-box value
        }

        // Step 3: XOR the round_counter with the 4 bits from (KEYSIZE - 61) to (KEYSIZE - 61 - 4) for 80-bit key, or (KEYSIZE - 62) to (KEYSIZE - 62 - 4) for 128-bit key
        // Awkward since this goes across byte boundaries, do it in two steps
        if (KEYSIZE == 80) {
            key[19/8] = (key[19/8] & 0xF0) | ((key[19/8] & 0x0F) ^ (round_counter & 0x1E)); // XOR k19,k18,k17,k16 with the leftmost 4 bits of the 5-bit round_counter
            key[15/8] = (key[15/8] & 0x7F) | (((key[15/8] >> 7) ^ (round_counter & 0x01)) << 7); // XOR k15 with the rightmost bit of the 5-bit round_counter
        }
        else if (KEYSIZE == 128) {
            key[66/8] = (key[66/8] & 0xF8) | ((key[66/8] & 0x07) ^ (round_counter & 0x1C)); // XOR k66,k65,k64 with the leftmost 3 bits of the 5-bit round_counter
            key[63/8] = (key[63/8] & 0x3F) | (((key[63/8] >> 6) ^ (round_counter & 0x03)) << 6); // XOR k63,k62 with the rightmost 2 bits of the 5-bit round_counter
        }

        // subkey = leftmost 64 bits
        subkeys[round_counter - 1] = leftmost64(key);
    }

    return subkeys;
}


/**********************
*** ROUND FUNCTIONS ***
**********************/
uint64_t add_round_key(uint64_t state, uint64_t round_key) {
    return state ^ round_key;
}

/**
 * Applies the s-box to the current state
 * @param state the 64-bit current state of the cipher
 * @returns the updated 64-bit state with the s-box applied
 */
uint64_t sbox_layer(uint64_t state) {
    uint64_t output = 0;
    for (int i = 0; i < KEYSIZE/8; i++) {
        output <<= 4;
        output |= sbox[(state >> (60 - i)) & 0x000000000000000F];
    }
    return output;
}

/**
 * Applies the P permutation to the current state
 * @param state the 64-bit current state of the cipher
 * @returns the updated 64-bit state with the P permutation applied
 */
uint64_t p_layer(uint64_t state) {
    uint64_t output = 0;
    for (int i = 0; i < 64; i++) {
        output <<= 1;
        output |= (state >> (64 - perm[i])) & 0x0000000000000001; 
    }
    return output;
}


/**************
*** PRESENT ***
**************/
// Best to think of state as consisting of 16 4-bit nibbles
uint64_t present(uint64_t input, uint8_t *key) {
    // generateRoundKeys
    // FOR i = 1 TO 31
    //      addRoundKey(STATE, Ki)
    //      sBoxLayer(STATE)
    //      pLayer(STATE)
    // addRoundKey(STATE, K32)
    
    uint64_t *subkeys = generate_round_keys(key);

    uint64_t state = input;
    for (int i = 0; i < 31; i++) {
        state = add_round_key(state, subkeys[i]);
        state = sbox_layer(state);
        state = p_layer(state);
    }

    state = add_round_key(state, subkeys[31]);

    free(subkeys);
    return state;
}


/**************
*** TESTING ***
**************/
/**
 * Consists of 31 rounds
 * Uses 64-bit blocks
 * Supports 80-bit of 128-bit keys
 */
int main() {    
    // Set test variables for the cipher
    uint64_t plaintext = 0x9474B8E8C73BCA7D;

    uint8_t key[10] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09
    };

    // Encrypt
    uint64_t ciphertext = present(plaintext, key);

    // Decrypt
    uint64_t decrypted_plaintext = present(ciphertext, key);

    // Print results
    printf("plaintext = %016lx\n\r", plaintext);
    printf("ciphertext = %016lx\n\r", ciphertext);
    printf("decrypted_plaintext = %016lx\n\r", decrypted_plaintext);

    // Sanity check the results
    if (memcmp(&plaintext, &ciphertext, 8) == 0) {
        printf("ERROR: Plaintext and ciphertext ARE the same!\n\r");
    }
    if (memcmp(&plaintext, &decrypted_plaintext, 8) != 0) {
        printf("ERROR: Plaintext and decrypted_plaintext are NOT the same!\n\r");
    }

    return 0;
}