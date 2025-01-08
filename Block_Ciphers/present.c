#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
#define KEYSIZE 80 // in BITS, can be 80 or 128

uint8_t sbox[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};

uint8_t inv_sbox[16] = {0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

// P[i] = (i*16) mod 63, except for P[63] = 63
uint8_t perm[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

uint8_t inv_perm[64] = {
    0, 4,  8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    1, 5,  9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63
};


/***********************
*** HELPER FUNCTIONS ***
***********************/
void print_block(uint64_t block) {
    for (int i = 63; i >= 0; i--) {
        printf("%ld", (block >> i) & 0x0000000000000001);
    }
    printf("\n");
}

void print_byte(uint8_t byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 0x01);
    }
    printf("\n");
}

void print_key(uint8_t* key) {
    for (int i = KEYSIZE/8 - 1; i >= 0; i--) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (key[i] >> j) & 0x01);
        }
    }
    printf("\n");
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
        output |= key[(KEYSIZE/8 - 1) - i];
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
    // subkey[0] = leftmost 64 bits of key of key
    // For rounds 1 through 31:
    //      Step 1: [k79,k78,...,k1,k0] = [k18,k17,...,k20,k19]
    //      Step 2: [k79,k78,k77,k76] = S[k79,k78,k77,k76]
    //      Step 3: [k19,k18,k17,k16,k15] = [k19,k18,k17,k16,k15] XOR round_counter
    //      subkey[round_counter] = leftmost 64 bits
    
    /*** 128-bit KEY FUNCTION ***/
    // subkey[0] = leftmost 64 bits of key
    // For rounds 1 through 31:
    //      Step 1: [k127,k126,...,k1,k0] = [k66,k65,...,k68,k67]
    //      Step 2: [k127,k126,k125,k124] = S[k127,k126,k125,k124]
    //      Step 3: [k123,k122,k121,k120] = S[k123,k122,k121,k120]
    //      Step 4: [k66,k65,k64,k63,k62] = [k66,k65,k64,k63,k62] XOR round_counter
    //      subkey[round_counter] = leftmost 64 bits of key

    uint64_t* subkeys = (uint64_t*)calloc(32, sizeof(uint64_t));

    // Copy the key to preserve its original value, since the key will be altered while generating the subkeys
    uint8_t *key_copy = calloc(KEYSIZE/8, sizeof(uint8_t));
    memcpy(key_copy, key, KEYSIZE/8);

    // Get the first subkey
    subkeys[0] = leftmost64(key); // Subkey for round 1

    // Frustratingly, the rounds are 1-indexed, but the round-counter is 0-indexed. So, for round X you must use the round_counter value of X-1
    // We already generated subkey[0], so start at 1 and go to 31 (inclusive) for a total of 32 subkeys
    // This generates a key for all 31 rounds, plus an extra subkey needed to perform the final add_round_key() operation
    for (uint8_t round_counter = 1; round_counter <= 31; round_counter++) {
        // Step 1: rotate key left by 61
        for (int i = 0; i < 61; i++) {
            rotate_left(key);
        }

        // Step 2: set 4 leftmost bits to s-box values for 80-bit key, or 8 leftmost bits for 128-bit key
        uint8_t msb_nibble = key[KEYSIZE/8 - 1] >> 4; // Get the MSB nibble as input to the s-box
        key[KEYSIZE/8 - 1] &= 0x0F; // Set the nibble to 0
        key[KEYSIZE/8 - 1] |= sbox[msb_nibble] << 4; // Set MSB nibble to the s-box value

        if (KEYSIZE == 128) {
            uint8_t msb_nibble = key[KEYSIZE/8 - 1] & 0x0F; // Get the 2nd MSB nibble as input to the s-box
            key[KEYSIZE/8 - 1] &= 0xF0; // Set the nibble to 0
            key[KEYSIZE/8 - 1] |= sbox[msb_nibble]; // Set 2nd MSB nibble to the s-box value
        }

        // Step 3: XOR the round_counter with the 4 bits from (KEYSIZE - 61) to (KEYSIZE - 61 - 4) for 80-bit key, or (KEYSIZE - 62) to (KEYSIZE - 62 - 4) for 128-bit key
        // Awkward since this goes across byte boundaries, so do it in two steps
        if (KEYSIZE == 80) {
            key[19/8] = (key[19/8] & 0xF0) | ((key[19/8] & 0x0F) ^ ((round_counter & 0x1E) >> 1)); // XOR k19,k18,k17,k16 with the leftmost 4 bits of the 5-bit round_counter
            key[15/8] = (key[15/8] & 0x7F) | (((key[15/8] >> 7) ^ (round_counter & 0x01)) << 7); // XOR k15 with the rightmost bit of the 5-bit round_counter
        }
        else if (KEYSIZE == 128) {
            key[66/8] = (key[66/8] & 0xF8) | ((key[66/8] & 0x07) ^ ((round_counter & 0x1C) >> 2)); // XOR k66,k65,k64 with the leftmost 3 bits of the 5-bit round_counter
            key[63/8] = (key[63/8] & 0x3F) | (((key[63/8] >> 6) ^ (round_counter & 0x03)) << 6); // XOR k63,k62 with the rightmost 2 bits of the 5-bit round_counter
        }

        // subkey = leftmost 64 bits of the working key
        subkeys[round_counter] = leftmost64(key);
    }

    // Set the key back to its original value before returning to preserve the starting key
    memcpy(key, key_copy, KEYSIZE/8);

    return subkeys;
}


/**********************
*** ROUND FUNCTIONS ***
**********************/
/**
 * Add the round key to the current state (addition modulo 2 with no carry is the same as performing an XOR)
 * @param state the 64-bit current state of the cipher 
 * @param round_key the 64-bit round key (subkey) to XOR with
 * @returns the 64-bit result of the XOR operation between the state and round_key
 */
uint64_t add_round_key(uint64_t state, uint64_t round_key) {
    return state ^ round_key;
}

/**
 * Applies the s-box to the current state
 * @param state the 64-bit current state of the cipher
 * @param mode determines the mode of operation ('e' for encrypting, 'd' for decrypting), determines to use the original s-box or the inverse
 * @returns the updated 64-bit state with the s-box applied
 */
uint64_t sbox_layer(uint64_t state, char mode) {
    uint64_t output = 0;
    for (int i = 0; i < 64; i+=4) {
        output <<= 4;
        output |= (mode == 'e') ? sbox[(state >> (60 - i)) & 0x000000000000000F] : inv_sbox[(state >> (60 - i)) & 0x000000000000000F];
    }
    return output;
}

/**
 * Applies the P permutation to the current state
 * @param state the 64-bit current state of the cipher
 * @param mode determines the mode of operation ('e' for encrypting, 'd' for decrypting), determines to use the original permutation or the inverse
 * @returns the updated 64-bit state with the P permutation applied
 */
uint64_t p_layer(uint64_t state, char mode) {
    uint64_t output = 0;
    for (int i = 0; i < 64; i++) {
        // Permutation read as "bit i of the input state is moved to bit position P(i) in the output state"
        output |= ((state >> i) & 0x0000000000000001) << ((mode == 'e') ? perm[i] : inv_perm[i]); 
    }
    return output;
}


/**************
*** PRESENT ***
**************/
/**
 * Perform the PRESENT block cipher on a 64-bit input for encryption
 * @param input the 64-bit input block to perform the cipher on (plaintext)
 * @param key pointer to the 80-bit or 128-bit key to use for the cipher
 * @returns the 64-bit resulting ciphertext
 */
uint64_t present_encrypt(uint64_t input, uint8_t *key) {
    // generateRoundKeys
    // FOR i = 1 TO 31
    //      addRoundKey(STATE, Ki)
    //      sBoxLayer(STATE)
    //      pLayer(STATE)
    // addRoundKey(STATE, K32)
    
    uint64_t *subkeys = generate_round_keys(key); // 0 - 31 (round 1-31, plus the last add_round_key)

    uint64_t state = input;
    for (int i = 0; i < 31; i++) {
        state = add_round_key(state, subkeys[i]);
        state = sbox_layer(state, 'e');
        state = p_layer(state, 'e');
    }

    state = add_round_key(state, subkeys[31]);

    free(subkeys);
    return state;
}

/**
 * Perform the PRESENT block cipher on a 64-bit input for decryption
 * @param input the 64-bit input block to perform the cipher on (ciphertext)
 * @param key pointer to the 80-bit or 128-bit key to use for the cipher
 * @returns the 64-bit resulting plaintext
 */
uint64_t present_decrypt(uint64_t input, uint8_t *key) {
    // generateRoundKeys
    // addRoundKey(STATE, K32)
    // FOR i = 31 TO 1
    //      inv_pLayer(STATE)
    //      inv_sBoxLayer(STATE)
    //      addRoundKey(STATE, Ki)
    
    uint64_t *subkeys = generate_round_keys(key); // 0 - 31 (round 1-31, plus the last add_round_key)

    uint64_t state = input;
    state = add_round_key(state, subkeys[31]);

    for (int i = 30; i >= 0; i--) {
        state = p_layer(state, 'd');
        state = sbox_layer(state, 'd');
        state = add_round_key(state, subkeys[i]);
    }
    
    free(subkeys);
    return state;
}


/**************
*** TESTING ***
**************/
int main() {    
    // Set test variables for the cipher
    // Using test vector from the PRESENT paper (https://www.iacr.org/archive/ches2007/47270450/47270450.pdf)
    uint64_t plaintext = 0x0000000000000000;

    uint8_t key[10] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };

    // Encrypt
    uint64_t ciphertext = present_encrypt(plaintext, key);

    // Decrypt
    uint64_t decrypted_plaintext = present_decrypt(ciphertext, key);

    // Print results
    printf("plaintext = %016lx\n", plaintext);
    printf("ciphertext = %016lx\n", ciphertext);
    printf("decrypted_plaintext = %016lx\n", decrypted_plaintext);

    // Sanity check the results
    if (memcmp(&plaintext, &ciphertext, 8) == 0) {
        printf("ERROR: Plaintext and ciphertext ARE the same!\n");
    }
    if (memcmp(&plaintext, &decrypted_plaintext, 8) != 0) {
        printf("ERROR: Plaintext and decrypted_plaintext are NOT the same!\n");
    }

    return 0;
}