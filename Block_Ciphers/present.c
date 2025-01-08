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
    printf("\n");
}

void print_halfblock(uint32_t halfblock) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (halfblock >> i) & 0x0000000000000001);
    }
    printf("\n");
}

void print_byte(uint8_t byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 0x01);
    }
    printf("\n");
}

void print_nibble(uint8_t byte) {
    for (int i = 3; i >= 0; i--) {
        printf("%d", (byte >> i) & 0x01);
    }
    printf("\n");
}

void print_round(uint8_t byte) {
    for (int i = 4; i >= 0; i--) {
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
    // printf("\toriginal key = "); print_key(key);

    // Store first bit for wrap-around
    uint8_t carry = (key[KEYSIZE/8 - 1] >> 7) & 0x01;
    // printf("\tTop bit = %d\n", carry);

    // Rotate all bytes except first
    for (int i = KEYSIZE/8 - 1; i > 0; i--) {
        // printf("\t[%d] Before = ", i); print_byte(key[i]);
        key[i] = (key[i] << 1) | ((key[i-1] >> 7) & 0x01);
        // printf("\t[%d] After  = ", i); print_byte(key[i]);
    }
    
    // Rotate first byte with the wrap-around carry
    // printf("\t[0] Before = "); print_byte(key[0]);
    key[0] = (key[0] << 1) | carry;
    // printf("\t[0] After  = "); print_byte(key[0]);

    // printf("\trotated_key = "); print_key(key);
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

    // printf("main key = "); print_key(key);
    uint64_t* subkeys = (uint64_t*)calloc(32, sizeof(uint64_t));

    // Copy the key which will be altered while generating the subkeys
    uint8_t *key_copy = calloc(KEYSIZE/8, sizeof(uint8_t));
    memcpy(key_copy, key, KEYSIZE/8);
    // printf("key_copy = "); print_key(key_copy);

    // Get the first subkey
    subkeys[0] = leftmost64(key); // Round key 1
    printf("subkey[1] = "); print_block(subkeys[0]);

    for (uint8_t round_counter = 1; round_counter <= 31; round_counter++) {
        // printf("========================\nROUND %d\n========================\n", round_counter);
        // printf("starting key = "); print_key(key);
        // Step 1: rotate key left by 61
        for (int i = 0; i < 61; i++) {
            rotate_left(key);
        }
        // printf("[%d] rotated_key = ", round_counter); print_key(key);
        // printf("[%d] key[msb_nibble] = ", round_counter); print_byte(key[KEYSIZE/8 - 1]);

        // Step 2: set 4 leftmost bits to s-box values for 80-bit key, or 8 leftmost bits for 128-bit key
        uint8_t msb_nibble = key[KEYSIZE/8 - 1] >> 4; // Get the MSB nibble as input to the s-box
        key[KEYSIZE/8 - 1] &= 0x0F; // Set the nibble to 0
        key[KEYSIZE/8 - 1] |= sbox[msb_nibble] << 4; // Set MSB nibble to the s-box value

        // printf("[%d] msb_nibble = ", round_counter); print_nibble(msb_nibble);
        // printf("[%d] sbox[msb_nibble] = ", round_counter); print_nibble(sbox[msb_nibble]);
        // printf("[%d] s-box key = ", round_counter); print_key(key);
        // printf("[%d] new_key[msb_nibble] = ", round_counter); print_byte(key[KEYSIZE/8 - 1]);

        if (KEYSIZE == 128) {
            uint8_t msb_nibble = key[KEYSIZE/8 - 1] & 0x0F; // Get the 2nd MSB nibble as input to the s-box
            key[KEYSIZE/8 - 1] &= 0xF0; // Set the nibble to 0
            key[KEYSIZE/8 - 1] |= sbox[msb_nibble]; // Set 2nd MSB nibble to the s-box value
        }

        // Step 3: XOR the round_counter with the 4 bits from (KEYSIZE - 61) to (KEYSIZE - 61 - 4) for 80-bit key, or (KEYSIZE - 62) to (KEYSIZE - 62 - 4) for 128-bit key
        // Awkward since this goes across byte boundaries, do it in two steps

        // printf("[%d] round_counter = ", round_counter); print_round(round_counter);
        // printf("[%d] key[23-16] = ", round_counter); print_byte(key[19/8]);
        // printf("[%d]                  ^^^^\n", round_counter);
        // printf("[%d] key[15-8]  = ", round_counter); print_byte(key[15/8]);
        // printf("[%d]              ^\n", round_counter);

        if (KEYSIZE == 80) {
            key[19/8] = (key[19/8] & 0xF0) | ((key[19/8] & 0x0F) ^ ((round_counter & 0x1E) >> 1)); // XOR k19,k18,k17,k16 with the leftmost 4 bits of the 5-bit round_counter
            key[15/8] = (key[15/8] & 0x7F) | (((key[15/8] >> 7) ^ (round_counter & 0x01)) << 7); // XOR k15 with the rightmost bit of the 5-bit round_counter
        }
        else if (KEYSIZE == 128) {
            key[66/8] = (key[66/8] & 0xF8) | ((key[66/8] & 0x07) ^ ((round_counter & 0x1C) >> 2)); // XOR k66,k65,k64 with the leftmost 3 bits of the 5-bit round_counter
            key[63/8] = (key[63/8] & 0x3F) | (((key[63/8] >> 6) ^ (round_counter & 0x03)) << 6); // XOR k63,k62 with the rightmost 2 bits of the 5-bit round_counter
        }

        printf("[%d] final key = ", round_counter + 1); print_key(key);

        // subkey = leftmost 64 bits
        subkeys[round_counter] = leftmost64(key);

        // printf("subkey[%d] = ", round_counter); print_block(subkeys[round_counter - 1]);
    }

    // Set the key back to its original value
    // (Do this so I can use the variable name "key" in the above logic, rather than having to operate on "key_copy")
    memcpy(key, key_copy, KEYSIZE/8);

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
    // printf("\nstate = "); print_block(state);
    uint64_t output = 0;
    for (int i = 0; i < 64; i+=4) {
        output <<= 4;
        output |= sbox[(uint8_t)(state >> (60 - i)) & 0x000000000000000F];

        // printf("\nnibble[%d-%d] = 0x%02x = ", (60 - i + 3), (60 - i), (uint8_t)((state >> (60 - i)) & 0x000000000000000F)); print_byte((uint8_t)(state >> (60 - i)) & 0x000000000000000F);
        // printf("sbox[%d] = 0x%02x = ", (uint8_t)((state >> (60 - i)) & 0x000000000000000F), sbox[(state >> (60 - i)) & 0x000000000000000F]); print_byte(sbox[(state >> (60 - i)) & 0x000000000000000F]);
        // printf("output = "); print_block(output);
    }
    // printf("\nfinal output = "); print_block(output);
    return output;
}

/**
 * Applies the P permutation to the current state
 * @param state the 64-bit current state of the cipher
 * @returns the updated 64-bit state with the P permutation applied
 */
uint64_t p_layer(uint64_t state) {
    // printf("\nstate = "); print_block(state);
    uint64_t output = 0;
    for (int i = 0; i < 64; i++) {
        // Permutation read as "bit i of the input state is moved to bit position P(i) in the output state"
        // printf("\nBit %d of the input state is moved to bit position %d of the output state\n", i, perm[i]);
        // printf("input[%d] = %d\n", i, (state >> i) & 0x0000000000000001);
        output |= ((state >> i) & 0x0000000000000001) << perm[i]; 
        // printf("output = "); print_block(output);
    }
    // printf("\nfinal output = "); print_block(output);
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

    // For the sake of generating keys, the round counter starts at 1, and goes to 31 (inclusive, so 1 <= round_counter <= 31)
    for (int i = 0; i < 31; i++) {
        printf("\nsubkey[%d] = ", i); print_block(subkeys[i]);
        state = add_round_key(state, subkeys[i]);
        printf("[%d]add_key = ", i+1); print_block(state);
        state = sbox_layer(state);
        printf("[%d]sbox_layer = ", i+1); print_block(state);
        state = p_layer(state);
        printf("[%d]p_layer = ", i+1); print_block(state);
    }

    state = add_round_key(state, subkeys[31]);
    printf("\n[%d]FINAL_add_key = ", 32); print_block(state);

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
    uint64_t plaintext = 0x0000000000000000;
    // uint64_t plaintext = 0x9474b8e8c73bca7d;

    uint8_t key[10] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    // uint8_t key[10] = {
    //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //     0x08, 0x09
    // };

    // Encrypt
    printf("========================\nENCRYPTION\n========================\n");
    uint64_t ciphertext = present(plaintext, key);


    // Decrypt
    printf("========================\nDECRYPTION\n========================\n");
    uint64_t decrypted_plaintext = present(ciphertext, key);

    // Print results
    printf("========================\nRESULTS\n========================\n");
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