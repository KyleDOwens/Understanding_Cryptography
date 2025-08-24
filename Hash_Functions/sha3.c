#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/**
 * This is made to only work with string inputs. Modifications will be needed for file or binary calculations
 * This implementation operates on byte index inputs (meaning it does not work for inputs with bit lengths that are not byte multiples)
 */


/****************
*** CONSTANTS ***
****************/
/*
| Function | state width (b) | bit_rate (r) | capacity (c) | security level | output size |
|----------|-----------------|--------------|--------------|----------------|-------------|
| SHA3-224 |       1600      |     1152     |     448      |       112      |     224     |
| SHA3-256 |       1600      |     1088     |     512      |       128      |     256     |
| SHA3-384 |       1600      |      832     |     768      |       192      |     384     |
| SHA3-512 |       1600      |      576     |    1024      |       256      |     512     |
|----------|-----------------|--------------|--------------|----------------|-------------|
| SHAKE128 |       1600      |     1344     |     256      |       112      |     any     |
| SHAKE256 |       1600      |     1088     |     512      |       256      |     any     |
*/

// This implementation is performing SHA3-256
#define OUTPUT_BITS 256
#define STATE_BITS 1600
#define RATE_BITS 1088
#define WIDTH 25 // The total depth of each lane (AKA how many values in each lane)
#define CAPACITY_BITS (STATE_BITS - RATE_BITS) // This determines the security level!

#define MOD(x, n) (((x) % (n) + (n)) % (n))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n)))) 

int rho_offsets[5][5] = {
//   0    1    2    3    4   = x
    {  0,  36,   3, 105, 210},      // y = 0
    {  1, 300,  10,  45,  66},      // y = 1
    {190,   6, 171,  15, 253},      // y = 2
    { 28,  55, 153,  21, 120},      // y = 3
    { 91, 276, 231, 136,  78}       // y = 4
};

uint64_t RC[24] = {
    0x0000000000000001, 
    0x0000000000008082, 
    0x800000000000808a, 
    0x8000000080008000, 
    0x000000000000808b, 
    0x0000000080000001, 
    0x8000000080008081, 
    0x8000000000008009, 
    0x000000000000008a, 
    0x0000000000000088, 
    0x0000000080008009, 
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
};



/********************
*** PREPROCESSING ***
********************/
/**
 * Pad the message to be a multiple of the 512 bits
 * Will append a 1, then k zero bits, and then a 64-bit block at the end containing the original msg length
 * @param msg the original message to pad
 * @param len the length of msg in BYTES
 * @param padded (OUTPUT) a double pointer where the outputted padded message will be put
 * @param len_padded (OUTPUT) the length of the padded message in BYTES
 */
void pad_msg(uint8_t *msg, int len, uint8_t **padded, int *len_padded) {
    // Calculate the number of 0s needed, k 
    // The message must have the 2-bit suffix added regardless of length
    // Pads the message by adding 10*1, where 0* = 0000...0
    // Note that 0* can be the empty string, so the smallest possible padding would be the suffix + '11'
    int k = (RATE_BITS - ((8*(len) + 2) % RATE_BITS)) % RATE_BITS; // The +2 accounts for the suffix and the minimum possible padding
    
    // Create the new padded message
    int remainder = ((8*(len) + 2 + k) % 8) ? 1 : 0;
    *len_padded = ((8*(len) + 2 + k) / 8) + remainder;
    *padded = malloc(*len_padded);
    memset(*padded, 0, *len_padded); // Set all bits to 0
    memcpy(*padded, msg, len); // Copy over the original message

    // Apply the suffix and padding bits
    // For this simpler implementation, the msg will ALWAYS be aligned on a byte boundary, so we can safely apply the suffix on the first padding byte
    // If we have multiple bytes of padding, the first byte of padding will always be SUFFIX || 10*, and the last byte will always be 0*1
    (*padded)[len] = 0x06; // Make the first bits SUFFIX || 10* in the first padding byte, which is 01 || 10* = 01100000 = 0x06 (in little endian)
    (*padded)[*len_padded - 1] |= 0x80; // Make the last bit in the last padding byte 1
}



/***************
*** KECCAK-f ***
***************/
/**
 * Every bit in the state is XOR'ed with the 10 bits "in its neighborhood"
 * (Visualize the state as a 5x5 grid that is 64 bits deep. This function XORs the bit with two columns around the column the bit is in)
 * This implementation uses the optimized implementation by performing all these calculations all at once rather than each bit at a time
 */
void theta(uint64_t state[5][5]) {
    uint64_t C[5] = {0};
    uint64_t D[5] = {0};

    // Adds up all of the columns via XOR, and store in C
    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
    }

    // XORs the columns that are "in the same neighborhood"
    for (int x = 0; x < 5; x++) {
        D[x] = C[MOD(x - 1, 5)] ^ ROTL(C[MOD(x + 1, 5)], 1);
    }

    // Add the original bits within each lane to the columns "in its neighborhood"
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[x][y] = state[x][y] ^ D[x];
        }
    }
}


/**
 * Rotates each lane in the state
 * Can think of "rho" for "rotation"
 */
void rho(uint64_t state[5][5]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[x][y] = ROTL(state[x][y], rho_offsets[x][y]); // Rotate the current lane
        }
    }
}

/**
 * Permutes each lane in the state
 * Can think of "pi" for "permutation"
 */
void pi(uint64_t state[5][5]) {
    uint64_t temp[5][5];

    // Perform the permutations
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            temp[x][y] = state[MOD(x + 3*y, 5)][x];
        }
    }

    // Copy over the permuted results back into the state variable
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[x][y] = temp[x][y];
        }
    }
}


/**
 * Chi step operates on lanes, and XORS the lane with the logical AND of the inverse of nearby lanes
 */
void chi(uint64_t state[5][5]) {
    uint64_t temp[5][5];

    // Perform the permutations
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            temp[x][y] = state[x][y] ^ (~state[MOD(x + 1, 5)][y] & (state[MOD(x + 2, 5)][y]));
        }
    }

    // Copy over the permuted results back into the state variable
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[x][y] = temp[x][y];
        }
    }
}


/**
 * Iota adds in a predefined constant to the lane A[0][0]
 */
void iota(uint64_t state[5][5], int round_num) {
    // XOR in the round constant
    state[0][0] = state[0][0] ^ RC[round_num];
}


/**
 * Perform the overall Keccak-f round function
*/
void keccak_f(uint64_t state[5][5]) {
    for (int i = 0; i < 24; i++) {
        printf("\n\n========================= ROUND %d =========================\n", i);
        for (int i = 0; i < 25; i++) {
            printf("%lx", state[i % 5][i / 5]);
        }
        printf("\n");

        theta(state);
        printf("-----THETA-----\n");
        for (int i = 0; i < 25; i++) {
            printf("%lx", state[i % 5][i / 5]);
        }
        printf("\n");

        rho(state);
        pi(state);
        printf("-----RHO PI-----\n");
        for (int i = 0; i < 25; i++) {
            printf("%lx", state[i % 5][i / 5]);
        }
        printf("\n");

        chi(state);
        printf("-----CHI-----\n");
        for (int i = 0; i < 25; i++) {
            printf("%lx", state[i % 5][i / 5]);
        }
        printf("\n");

        iota(state, i);
    }

    printf("\n\n========================= FINAL =========================\n");
    for (int i = 0; i < 25; i++) {
        printf("%lx", state[i % 5][i / 5]);
    }
    printf("\n\n");
}


/**********************
*** CORE SHA-3 HASH ***
**********************/
uint64_t extend_block(uint8_t* block) {
    uint64_t extended_block = 0;
    for (int i = 0; i < 8; i++) {
        // printf("\tByte: %lx\n", (uint64_t)block[i]);
        extended_block |= ((uint64_t)block[i]) << (8*i);
    }
    return extended_block;
}

uint8_t* sha3(uint8_t *msg) {
    /*** PREPROCESSING ***/
    // Pad the message
    uint8_t *padded_msg = NULL;
    int padded_len = 0;
    pad_msg(msg, strlen(msg), &padded_msg, &padded_len);

    // for (int i = 0; i < padded_len; i++) {
    //     if (i == strlen(msg)) {
    //         printf("|");
    //     }
    //     printf("%02x", padded_msg[i]);
    // }
    // printf("\n");


    // Create the internal SHA-3 state 
    uint64_t state[5][5] = {0}; // Each index is a lane, which contains 64 bits, for a total of 5*5*64 = 1600 state bits
    
    /*** ABSORBING PHASE ***/
    // Break padded message into RATE_BITS sized blocks
    for (int i = 0; i < padded_len; i += RATE_BITS/8) {
        uint8_t* block = padded_msg + i*RATE_BITS;

        // XOR the current block with the RATE component of the state
        for (int j = 0; j < RATE_BITS/(8*8); j++) { // Loop through by LANE
            // printf("Extended block: %lx\n", extend_block(block + 8*j));
            state[j % 5][j / 5] ^= extend_block(block + 8*j);
        }

        // Perform the Keccak round function
        keccak_f(state);
    }

    /*** SQUEEZING PHASE ***/
    uint8_t* output = malloc(OUTPUT_BITS/8);
    int offset = 0;

    // Squeeze until the desired output length is reached
    while (offset < OUTPUT_BITS/8) {
        // Extract output from the RATE component of the state 
        for (int i = 0; i < RATE_BITS/(8*8); i++) { // Loop through by LANE
            uint64_t lane = state[i % 5][i / 5];

            // Fill the output up one BYTE at a time so we do not accidentally overflow
            for (int j = 0; j < 64/8; j++) {
                output[offset] = (uint8_t)((lane >> 8*j) & 0xFF);
                offset++;
                
                // Once the output is full, return
                if (offset >= OUTPUT_BITS/8) {
                    free(padded_msg);
                    return output;
                }
            }
        }

        // Perform the Keccak round function
        keccak_f(state);
    }
}



/**************
*** TESTING ***
**************/
// Test examples: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing
int main() {    
    // Set test variables for the cipher
    uint8_t msg[] = "abc";
    printf("message = %s\n", msg);

    uint8_t *digest = sha3(msg);
    printf("digest = %s\n", digest);
    printf("       = ");
    for (int i = 0; i < OUTPUT_BITS/8; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free(digest);
    return 0;
}