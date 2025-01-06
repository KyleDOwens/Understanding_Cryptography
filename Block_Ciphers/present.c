#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
#define KEYSIZE 80 // 80 or 128

uint8_t S[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
uint8_t inv_S[16] = {0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

// P[i] = (i*16) mod 63, except for P[63] = 63
uint8_t P[64] = {
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
 * @param key the 80-bit or 128-bit main key
 */
uint64_t* generate_round_keys(uint8_t *key) {
    uint64_t subkeys[31] = {0};

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
}


/**********************
*** ROUND FUNCTIONS ***
**********************/
uint64_t add_round_key(uint64_t state, uint64_t round_key) {
    return state ^ round_key;
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
    return 0;
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
    return 0;
}