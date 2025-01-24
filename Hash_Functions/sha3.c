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

// Keccak parameters (refer to table below for valid combinations)
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
#define OUTPUT_SIZE 256
#define STATE_WIDTH 1600
#define BIT_RATE 1088
#define CAPACITY (STATE_WIDTH - BIT_RATE) // This determines the security level!

// Note that this table is NOT organized in the correct visual way for SHA3 ((0,0) should be in the center)
// Rather, this is organized how the offets are being calculate in this implementation: (x, y) results in a memory offset of (x + 5*y)
uint8_t rho_offsets[25] = {
//   0    1    2    3    4   = X
      0,   1, 190,  28,  91,        // y = 0
     36,  300,  6,  55, 276,        // y = 1
      3,  10, 171, 153, 231,        // y = 2
    105,  45,  15,  21, 136,        // y = 3
    210,  66, 253, 120,  78,        // y = 4
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
    int k = (BIT_RATE - 8*(len + 1)) % BIT_RATE; // The +1 accounts for the suffix and the minimum possible padding
    if (k < 0) {
        k += BIT_RATE;
    }
    
    // Create the new padded message
    *len_padded = len + (k+1)/8 + 64/8;
    *padded = malloc(*len_padded);

    memcpy(*padded, msg, len); // Copy over the original message
    memset(*padded + len, 0, (*len_padded - len)); // Set all padded bits to 0

    // Apply the suffix to the first padded byte
    // The first byte of padding is:   suffix || 10*1   =   01 || 10*1
    // So if more than 1 byte is being padded, the first padding byte is 01100000, and the last byte is 0x01
    if ((*len_padded - len) > 1) {
        memset(*padded + len, 0x60, 1);
        memset(*padded + *len_padded - 1, 0x01, 1);
    }
    // Otherwise if there is only 1 byte of padding needed, it is 01100001
    else {
        memset(*padded + len, 0x61, 1);
    }
}


/**************
*** KECCAK  ***
**************/
void combine_into_state(uint8_t *r, uint8_t *c, uint64_t *state) {
    for (int i = 0; i < BIT_RATE/8; i++) {
        state[i] = r[i];
    }
    for (int i = 0; i < CAPACITY/8; i++) {
        state[BIT_RATE/8 + i] = c[i];
    }
}

/**
 * This is ordered such that lane (0, 0) is the first 64 bits, (0, 1) is bits 64-128, and so on
 */
uint64_t get_lane(int x, int y, uint64_t *state) {
    return state[x + 5*y];
}

void set_lane(int x, int y, uint64_t *state, uint64_t new_value) {
    state[x + 5*y] = new_value;
}

/**
 * Rotates the bits in a word w n bits to the right
 * @param w word to rotate
 * @param n number of bits to rotate right
 * @returns the resulting rotated value
 */
uint64_t rotr(uint64_t w, int n) {
    return (w >> n) | (w << (64 - n));
}

int mod5(int n) {
    n = n % 5;
    if (n < 5) {
        n += 5;
    }
    return n;
}

/**
 * Every bit in the state is XOR'ed with the 10 bits "in its neighborhood"
 * (Visualize the state as a 5x5 grid that is 64 bits deep. This function XORs the bit with two columns around the column the bit is in)
 * This implementation uses the optimized implementation, by performing all these calculations all at once, rather than each bit at a time
 */
void theta(uint64_t *state) {
    uint64_t C[5] = {0};
    uint64_t D[5] = {0};

    // Adds up all of the columns via XOR, and store in C
    for (int x = 0; x < 5; x++) {
        C[x] = get_lane(x, 0, state) ^ get_lane(x, 1, state) ^ get_lane(x, 2, state) ^ get_lane(x, 3, state) ^ get_lane(x, 4, state);
    }

    // XORs the columns that are "in the same neighborhood"
    for (int x = 0; x < 5; x++) {
        D[x] = C[mod5(x - 1)] ^ rotr(C[mod5(x + 1)], 1);
    }

    // Add the original bits within each lane to the columns "in its neighborhood"
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint64_t new_lane = get_lane(x, y, state) ^ D[x];
            set_lane(x, y, state, new_lane);
        }
    }
}

/**
 * Rotates each lane in the state
 * Can think of "rho" for "rotation"
 */
void rho(uint64_t *state) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint64_t new_lane = rotr(get_lane(x, y, state), rho_offsets[x + 5*y]); // Rotate the current lane
            set_lane(x, y, state, new_lane);
        }
    }
}

/**
 * Permutes each lane in the state
 * Can think of "pi" for "permutation"
 */
void pi(uint64_t *state) {

}

void keccak_f(uint8_t *r, uint8_t *c, uint64_t *state) {
    combine_into_state(r, c, state);

    theta(state);
    rho(state);
}


/**************
*** ABSORB  ***
**************/



/**********************
*** CORE SHA-3 HASH ***
**********************/
uint8_t* sha3(uint8_t *msg) {
    /*** PREPROCESSING ***/
    // Pad the message
    uint8_t *padded = NULL;
    int padded_len = 0;
    pad_msg(msg, strlen(msg), &padded, &padded_len);
    // Breaking the padded message into blocks will be done in the main loop

    uint8_t *r = calloc(BIT_RATE/8, sizeof(uint8_t));
    uint8_t *c = calloc(CAPACITY/8, sizeof(uint8_t));
    uint64_t *state = calloc(STATE_WIDTH/8, sizeof(uint64_t));
    keccak_f(r, c, state);

    uint8_t *digest = malloc(OUTPUT_SIZE/8);
    memcpy(digest, state, OUTPUT_SIZE/8);

    // free(padded);
    return digest;
}



/**************
*** TESTING ***
**************/
int main() {    
    // Set test variables for the cipher
    uint8_t msg[] = "sha-3 test msg!";
    printf("message = %s\n", msg);

    uint8_t *digest = sha3(msg);
    printf("digest = %s\n", digest);
    printf("       = ");
    for (int i = 0; i < OUTPUT_SIZE/8; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free(digest);
    return 0;
}
