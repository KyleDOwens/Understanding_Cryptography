#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


#define KEYSIZE 128 // Can be 128, 192, or 256


/****************
*** CONSTANTS ***
****************/
/** 
 * Substitution box (s-box) for AES
 * Provided an input byte, the MSB nibble chooses the ROW and the LSB nibble chooses the COLUMN
 * 
 * This S-box has strong algebraic structure, and can be viewed as performing two functions on the input:
 *     A[i] --> Inversion on GF(2^8) --> B'[i] --> Affine mapping --> B[i]
 * Where A denotes the input state, and B the substituted output state
 * The "inversion on GF(2^8)" step computes the inverse of the element A[i] in the Galois field GF(2^8)
 * The "affine mapping" step performs a multiplication with a constant bit-matrix, along with addition with a constant bit-vector
 * These steps provide (1) strong nonlinearity to protect against analytical attacks, and (2) protection against finite field inversion attacks
 * Rather than computing these steps in this implementation, this constant lookup table is used instead
 * This is often done for software implementations, although for some hardware implementations it can be advantageous to design the circuits to compute these steps instead
 */
uint8_t sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   // F
};


/***********************
*** HELPER FUNCTIONS ***
***********************/
void print_byte(uint8_t byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 0x01);
    }
    printf("\n");
}

void print_block_m16(uint8_t *block) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            printf("0x%02x ", *(block + r*sizeof(uint8_t) + 4*c*sizeof(uint8_t)));
        }
        printf("\n");
    }
}

void print_block_m2(uint8_t *block) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            for (int j = 7; j >= 0; j--) {
                printf("%d", (*(block + r*sizeof(uint8_t) + 4*c*sizeof(uint8_t)) >> j) & 0x01);
            }
            printf(" ");
        }
        printf("\n");
    }
}

void print_key_16(uint8_t *key) {
    for (int i = 0; i < KEYSIZE/8; i++) {
        printf("0x%02x ", *(key + i*sizeof(uint8_t)));
    }
    printf("\n");
}

void print_key_2(uint8_t *key) {
    for (int i = 0; i < KEYSIZE/8; i++) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (*(key + i*sizeof(uint8_t)) >> j) & 0x01);
        }
        printf(" ");
    }
    printf("\n");
}

void print_key_m16(uint8_t *key) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < (KEYSIZE/8)/4; c++) {
            printf("0x%02x ", *(key + r*sizeof(uint8_t) + 4*c*sizeof(uint8_t)));
        }
        printf("\n");
    }
}

void print_key_m2(uint8_t *key) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < (KEYSIZE/8)/4; c++) {
            for (int j = 7; j >= 0; j--) {
                printf("%d", (*(key + r*sizeof(uint8_t) + 4*c*sizeof(uint8_t)) >> j) & 0x01);
            }
            printf(" ");
        }
        printf("\n");
    }
}


/************************
*** BYTE SUBSTITUTION ***
************************/
/**
 * Performs the ByteSubstitution layer on the current state block
 * This layer is a row of 16 parallel S-boxes, each with 8 input bits and 8 output bits
 * All 16 S-boxes are identical
 * @param state pointer to the current state, which will be directly modified during the substitution
 */
void byte_substitution(uint8_t *state) {
    // For each byte in the input, substitute it with the value from the S-box
    for (int i = 0; i < 128/8; i++) {
        state[i] = sbox[state[i]];
    }
}


/**********************
*** DIFFUSION LAYER ***
**********************/
/**
 * Consists of two sublayers: ShiftRows and MixColumn
 * This layer provides a large amount diffusion to the cipher, spreading out any single input changes to effect the a large amount of the output state
 * This layer performs linear operations i.e. DIFF(A) + DIFF(B) = DIFF(A + B)
 */

/**
 * Shift the given row to the right by the needed amount
 * @param state the current 128-bit state to shift
 * @param row the row being shifted (0-indexed)
 */
void shift_row(uint8_t *state, int row) {
    // Perform shift the row depending on the row value
    for (int shift_num = (4 - row) % 4; shift_num > 0; shift_num--) {
        // Save the last value in the row to wrap around at the end
        uint8_t wrap = state[row + 4*3];
        
        // Shift the row a single byte to the right
        for (int col = 3; col > 0; col--) {
            state[row + 4*col] = state[row + 4*(col - 1)];
        }

        // Replace the (wrapping the last value back to the start)
        state[row + 4*0] = wrap;
    }
}

 /**
  * Performs the ShiftRows sublayer on the current state by cyclically shifting the rows of the state:
  *     - First row is left unchanged
  *     - Second row is shifted 3 bytes to the right
  *     - Third row is shifted 2 bytes to the right
  *     - Fourth row is shifted 1 byte to the right
  * @param state the current 128-bit state to shift
  */
void shift_rows(uint8_t *state) {
    for (int row = 0; row < 4; row++) {
        shift_row(state, row);
    }
}


/**
 * Performs the MixColum sublayer
 * This is the primary function that introduces diffusion into the cipher, since every input byte influences 4 output bytes
 */
void mix_column(uint8_t *state) {

    uint32_t matrix = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02
    };

    uint8_t output[128/8] = {0};

    for (int col = 0; col < 4; col++) {
        // Treat each column as a vector of size 4
        uint8_t col_vect[4] = {state[0 + 4*col], state[1 + 4*col], state[2 + 4*col], state[3 + 4*col]};

        // Multiply the column vector by the constant matrix
        // TODO
    }
}


/**************
*** TESTING ***
**************/
int main() {    
    // Set test variables for the cipher
    uint8_t plaintext[16] = {'a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
    uint8_t key[16] = {'k', 'k', 'k', 'k', 'e', 'e', 'e', 'e', 'y', 'y', 'y', 'y', '.', '.', '.', '.'};

    print_block_m16(plaintext); printf("\n");
    byte_substitution(plaintext);
    print_block_m16(plaintext); printf("\n");
    shift_rows(plaintext);
    print_block_m16(plaintext); printf("\n");

    // Print results
    // printf("plaintext = %016lx\n\r", plaintext);
    // printf("ciphertext = %016lx\n\r", ciphertext);
    // printf("decrypted_plaintext = %016lx\n\r", decrypted_plaintext);

    // Sanity check the results
    // if (memcmp(&plaintext, &ciphertext, 8) == 0) {
    //     printf("ERROR: Plaintext and ciphertext ARE the same!\n\r");
    // }
    // if (memcmp(&plaintext, &decrypted_plaintext, 8) != 0) {
    //     printf("ERROR: Plaintext and decrypted_plaintext are NOT the same!\n\r");
    // }

    return 0;
}