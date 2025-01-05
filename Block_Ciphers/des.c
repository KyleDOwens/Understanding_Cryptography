#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/***********************
*** HELPER FUNCTIONS ***
***********************/
void print_block(uint64_t block) {
    printf("Block = %ld = ", block);
    for (int i = 63; i >= 0; i--) {
        printf("%ld", (block >> i) & 0x0000000000000001);
    }
    printf("\n\r");
}


/*******************
*** PERMUTATIONS ***
*******************/
/**
 * Performs the initial permutation on a plaintext block
 * The actual function of this permutation is essentially a crosswiring
 * @param block a 64-bit plaintext block
 */
void initial_permutation(uint64_t *block) {
    // Vector of bit swaps to perform for the initial permutation
    // Read as: "the 1st bit of the output is taken from the 58th bit of the input" and so on
    uint8_t initial_perm[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    // Built the output block one bit at a time
    uint64_t output = 0;
    for (int i = 0; i < 64; i++) {
        output <<= 1;
        output |= (*block >> (64 - initial_perm[i])) & 0x0000000000000001; 
    }

    *block = output;
}

/**
 * Performs the final permutation on a plaintext block
 * The actual function of this permutation is essentially a crosswiring
 * @param block a 64-bit plaintext block
 */
void final_permutation(uint64_t *block) {
    // Vector of bit swaps to perform for the initial permutation
    // Read as: "the 1st bit of the output is taken from the 58th bit of the input" and so on
    uint8_t final_perm[64] = {
        40, 8, 48, 16, 56, 24, 64, 32, 
        39, 7, 47, 15, 55, 23, 63, 31, 
        38, 6, 46, 14, 54, 22, 62, 30, 
        37, 5, 45, 13, 53, 21, 61, 29, 
        36, 4, 44, 12, 52, 20, 60, 28, 
        35, 3, 43, 11, 51, 19, 59, 27, 
        34, 2, 42, 10, 50, 18, 58, 26, 
        33, 1, 41,  9, 49, 17, 57, 25
    };

    // Built the output block one bit at a time
    uint64_t output = 0;
    for (int i = 0; i < 64; i++) {
        output <<= 1;
        output |= (*block >> (64 - final_perm[i])) & 0x0000000000000001; 
    }

    *block = output;
}


/**************
*** TESTING ***
**************/
int main() {

    uint64_t block = 0x0000000000000001;
    print_block(block);
    initial_permutation(&block);
    print_block(block);
    final_permutation(&block);
    print_block(block);

    return 0;
}