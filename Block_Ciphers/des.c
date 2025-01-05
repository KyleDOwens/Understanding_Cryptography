#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/****************
*** CONSTANTS ***
****************/
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

uint8_t expand_perm[48] = {
    32,  1,  2,  3,  4,  5,  
     4,  5,  6,  7,  8,  9,  
     8,  9, 10, 11, 12, 13, 
    12, 13, 14, 15, 16, 17, 
    16, 17, 18, 19, 20, 21, 
    20, 21, 22, 23, 24, 25, 
    24, 25, 26, 27, 28, 29, 
    28, 29, 30, 31, 32,  1
};

// Each s-box is a lookup table mapping a 6-bit input to a 4-bit ouput
uint8_t sboxes[8][64] = {{
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,  
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,  
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0, 
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
},{
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,  
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,  
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15, 
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
},{
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,  
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,  
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
},{
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,  
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,  
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
},{
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9, 
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6, 
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14, 
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
},{
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
},{
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
},{
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
}};

uint8_t f_perm[32] = {
    16,  7, 20, 21, 29, 12, 28, 17, 
     1, 15, 23, 26,  5, 18, 31, 10, 
     2,  8, 24, 14, 32, 27,  3,  9, 
    19, 13, 30,  6, 22, 11,  4, 25
};

uint8_t pc1_perm[56] = {
    57, 49, 41, 33, 25, 17,  9,  1,
    58, 50, 42, 34, 26, 18, 10,  2, 
    59, 51, 43, 35, 27, 19, 11,  3,
    60, 52, 44, 36, 63, 55, 47, 39, 
    31, 23, 15,  7, 62, 54, 46, 38,
    30, 22, 14,  6, 61, 53, 45, 37,
    29, 21, 13,  5, 28, 20, 12,  4
};

uint8_t pc2_perm[56] = {
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
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
*** PERMUTATIONS ***
*******************/
/**
 * Performs a permutation on an input block
 * @param block the input block to permute. Can be any size <= 64 bits
 * @param from_size the size of the permutation input (block)
 * @param to_size the size the permutation output
 * @param perm pointer to the permutation vector to use
 * @returns the permuted block
 */
uint64_t permute(uint64_t block, int from_size, int to_size, uint8_t *perm) {
    // Built the output block one bit at a time
    uint64_t output = 0;
    for (int i = 0; i < to_size; i++) {
        output <<= 1;
        output |= (block >> (from_size - perm[i])) & 0x0000000000000001; 
    }

    return output;
}


/*****************
*** f FUNCTION ***
*****************/
/**
 * Takes in the right half of the previous round and the current round's key
 * Produces an XOR-mask used for encrypting the left half of the previous round's output
 * @param right the 32-bit right half of the previous round's output
 * @param key the 48-bit subkey for this round
 * @returns a 32-bit integer representing the f funcion's outputted keystream (to use to encrypt the left side)
 */
uint32_t f_function(uint32_t right, uint64_t subkey) {
    // Expand the 32-bit input to 48-bits
    uint64_t right_expand = permute(right, 32, 48, expand_perm);

    // XOR the expanded right side with the round subkey
    uint64_t xor_sbox_input = right_expand ^ subkey;
    
    // Break the xor results into eight 6-bit blocks
    uint8_t sbox_inputs[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 6*8; i+=6) {
        // Put the most significant 6 bits into input[0], which will be used with s-box 1 (sboxes[0])
        sbox_inputs[i/6] = (xor_sbox_input >> (42 - i)) & 0x000000000000003F;
    }

    // Feed the eight 6-bit blocks into substitution boxes (s-boxes)
    for (int i = 0; i < 8; i++) {
        uint8_t msb = (sbox_inputs[i] >> 5) & 0x1;
        uint8_t lsb = sbox_inputs[i] & 0x01;
        uint8_t sbox_row = (uint8_t)((msb << 1) | lsb); // Use the MSB and LSB to determine the row
        uint8_t sbox_col = (uint8_t)((sbox_inputs[i] >> 1) & 0x0F); // Use the inner 4 bits to determine the column

        sbox_inputs[i] = sboxes[i][16*sbox_row + sbox_col];
    }

    // Combine the resulting eight 4-bit outputs together
    uint32_t sbox_output = 0;
    for (int i = 0; i < 8; i++) {
        sbox_output <<= 4;
        sbox_output |= sbox_inputs[i];
    }

    // Permute the combined s-boxes outputs (which has been reduced to 32-bits)
    uint32_t output = (uint32_t)permute(sbox_output, 32, 32, f_perm);

    return output;
}


/*******************
*** KEY SCHEDULE ***
*******************/
/**
 * Given one half of a key, rotate it
 * @param half_key half of a key/subkey to rotate (either c0,...,c16 or d0,...,d16)
 * @param round_num the current round number, used to determine how much to rotate by
 * @returns the rotated key
 */
uint32_t left_shift(uint32_t half_key, int round_num) {
    // Rotate depending on the round number
    int num_rot = (round_num == 1 || round_num == 2 || round_num == 9 || round_num == 16) ? 1 : 2;
    for (int i = 0; i < num_rot; i++) {
        half_key = ((half_key << 1) & 0x0FFFFFFF) | ((half_key >> 27) & 0x00000001);
    }
    return half_key;
}

/**
 * Given one half of a key, rotate it
 * @param half_key half of a key/subkey to rotate (either c0,...,c16 or d0,...,d16)
 * @param round_num the current round number, used to determine how much to rotate by
 * @returns the rotated key
 */
uint32_t right_shift(uint32_t half_key, int round_num) {
    // No shift for round 1
    if (round_num == 1) {
        return half_key;
    }

    // Rotate depending on the round number
    int num_rot = (round_num == 2 || round_num == 9 || round_num == 16) ? 1 : 2;
    for (int i = 0; i < num_rot; i++) {
        half_key = (half_key >> 1) | (((half_key & 0x00000001) << 27) & 0x0FFFFFFF);
    }
    return half_key;
}

/**
 * Derives a round key (also known as subkeys)
 * Each key contains 48 bits from the 56-bit key
 * It's important to note that for decryption, C0 = C16 and D0 = D16.
 * @param c pointer to the first half (MSB to center) of the working key (NOT the subkey, the internal key to the transform functions)
 * @param d pointer to the last half (center to LSB) of the working key (NOT the subkey, the internal key to the transform functions)
 * @param round_num the current round number to generate the subkey for
 * @param mode whether encryption ("e") or decryption ("d") is being performed
 * @returns the current round's subkey
 */
uint64_t key_transform(uint32_t *c, uint32_t *d, int round_num, char mode) {
    // Rotate the keys (left for encryption, right for decryption)
    *c = (mode == 'e') ? left_shift(*c, round_num) : right_shift(*c, round_num);
    *d = (mode == 'e') ? left_shift(*d, round_num) : right_shift(*d, round_num);

    // Combine the rotated keys
    uint64_t combined_key = ((uint64_t)(*c) << 28) | ((uint64_t)(*d));

    // Compute the PC-2 permutation to produce the subkey (round key)
    uint64_t subkey = permute(combined_key, 56, 48, pc2_perm);

    return subkey;
}


/**********
*** DES ***
**********/
/**
 * TODO: write function documentation
 * TODO: implement decryption
 * TODO: perform tests
 */
uint64_t des(uint64_t input, uint64_t key, char mode) {
    /*** Perform the initial permutations ***/
    // Input permutation (plaintext/ciphertext)
    input = permute(input, 64, 64, initial_perm);

    // Key permutation
    // The reduction of the key to 56-bits is built into the initial key permutation PC-1
    uint64_t reduced_key = permute(key, 64, 56, pc1_perm);

    /*** Split into halves ***/
    // Split input text into two halves, L (left) and R (right)
    uint32_t l = (uint32_t) (input >> 32) & 0x00000000FFFFFFFF;
    uint32_t r = (uint32_t) input & 0x00000000FFFFFFFF;

    // Split the key into two halves, C and D
    uint32_t c = (uint32_t) (reduced_key >> 28) & 0x000000000FFFFFFF; // left half, MSB -> center
    uint32_t d = (uint32_t) reduced_key & 0x000000000FFFFFFF; // right half, center -> LSB

    /*** Start the blocks of the cipher ***/
    for (int round_num = 1; round_num <= 16; round_num++) {
        // Compute 48-bit subkey
        uint64_t subkey = key_transform(&c, &d, round_num, mode);

        // Perform f function
        uint32_t keystream = f_function(r, subkey);

        // Swap sides
        uint32_t temp = r;
        r = l ^ keystream;
        l = temp;
    }

    // Combine perform one last swap and combine left/right back together
    uint64_t output = (((uint64_t)r << 32) & 0xFFFFFFFF00000000) | (l & 0x00000000FFFFFFFF);

    // Perform the final permutations
    output = permute(output, 64, 64, final_perm);
    return output;
}
 

/**************
*** TESTING ***
**************/
int main() {    
    // Set test variables for the cipher
    uint64_t plaintext = 0x9474B8E8C73BCA7D;
    uint64_t key = 0x9474B8E8C73BCA7D;
        // Although the key for DES is 56-bits, it is often expanded to 64-bits by adding an odd parity every 8th bit (the 8th bit specifying the parity of the previous 7 bits)
        // For this implementation, use the 64-bit key 

    // Encrypt
    uint64_t ciphertext = des(plaintext, key, 'e');

    // Decrypt
    uint64_t decrypted_plaintext = des(ciphertext, key, 'd');

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