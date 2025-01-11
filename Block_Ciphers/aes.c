#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


#define KEYSIZE 128 // Can be 128, 192, or 256
#define NUMROUNDS (KEYSIZE == 128) ? 10 : ((KEYSIZE == 192) ? 12 : 14) // 10, 12, or 14 depending on the key size


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
    //00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 00
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 10
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 20
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 30
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 40
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 50
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 60
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 70
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 80
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 90
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A0
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B0
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C0
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D0
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E0
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   // F0
};

// The MSB nibble determines the column, the LSB nibble is the row
uint8_t inv_sbox[256] = {
    //00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 00
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 10
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 20
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 30
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 40
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 50
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 60
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 70
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 80
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 90
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // A0
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // B0
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // C0
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // D0
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // E0
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  // F0
};

uint8_t mixcolumn_matrix[16] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};

// Log table using 0xe5 (229) as the generator
uint8_t log_table[256] = {
    0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 
    0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18, 
    0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 
    0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e, 
    0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 
    0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3, 
    0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 
    0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74, 
    0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 
    0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1, 
    0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 
    0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80, 
    0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 
    0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5, 
    0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 
    0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba, 
    0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 
    0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47, 
    0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 
    0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05, 
    0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 
    0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd, 
    0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 
    0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec, 
    0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 
    0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e, 
    0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 
    0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d, 
    0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 
    0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d, 
    0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 
    0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38
};

// Anti-log (i.e. exponentiation) table for 0xe5
uint8_t antilog_table[256] = {
    0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 
    0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36, 
    0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 
    0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee, 
    0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 
    0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b, 
    0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 
    0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c, 
    0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 
    0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a, 
    0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 
    0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94, 
    0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 
    0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2, 
    0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 
    0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17, 
    0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 
    0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b, 
    0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 
    0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c, 
    0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 
    0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97, 
    0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 
    0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd, 
    0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 
    0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24, 
    0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 
    0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4, 
    0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 
    0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52, 
    0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 
    0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01
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


/****************************
*** GALOIS MULTIPLICATION ***
****************************/
/**
 * Computes the Galois field multiplication on the two inputs
 * https://www.samiam.org/galois.html
 * @param a the multiplicand
 * @param b the multiplier
 * @returns the result of a * b within GF(2^8)
 */
uint8_t compute_galois_mult(uint8_t a, uint8_t b) {
    /**
     * Set the product to zero
     * FOR i = 1 TO 8
     *     1) If the low bit of b is set, XOR a to the product (the same as addition)
     *     2) Find the high bit of a
     *     3) Shift a to the left
     *     4) If the previous high-bit was 1, XOR a with 0x1b = 00011011
     *     5) Rotate b to the right
     * 
     * 
     * Below is a more detailed explanation on what each step is doing, and why it is necessary (a basic understand of Galois fields is needed):
     * Set the product to zero
     * FOR i = 1 TO 8
     *     1) This step is the one actually performing the accumulation of the product (AKA it is multiplying a by the rightmost coefficient in the working polynomial b)
     *        On the first iteration this is the constant value 1 or 0. On the next iteration this is the coefficient for x, then x^2, and so on
     *        Rather than performing actual multiplication though, this step simply adds the current value of a to the product
     *        This works because over the courses of the algorithm, a and b will be shifted to adjust for what place value is being worked on
     *
     *     2) The high bit represents the coefficient for the highest degree power in the polynomial (which is x^7 in GF(2^8))
     *        We know the next step of the algorithm will shift a to the left, multiplying it by x (thus increasing the power of each term)
     *        So if the high bit is currently set, that means the current highest term will be increased in power, going to x^8, meaning a will have to be reduced after multiplying
     *        Keeping track of the current high bit lets us determine later if this reduction is needed
     *
     *     3) This multiplies a by x in preparation for the next coefficient (a = a*x)
     *        If the coefficient is 0, nothing will be added to the accumulated product
     *        If that coefficient is 1, because a has already been multiplied by x i times, value for a can just be added to the product 
     *
     *     4) If the high bit was previously set, then a must have overflowed from GF(2^8)
     *        So, it must be reduced by the field's chosen irreducible polynomial, P(x) (for AES, P(x) = x^8 + x^4 + x^3 + x + 1 = 00011011 = 0x1b)
     *        This is done by subtracting the irreducible polynomial from the product (which is the same as doing a bitwise XOR)
     * 
     *     5) At this point we are done "multiplying" the current rightmost coefficient
     *        So, shift b to the right to move the up to the next place value's coefficient, which will be "multiplied" on the next iteration 
     * 
     * 
     * You can think about this in terms of base-10 multiplication of two multi-digit numbers (assume you are doing the multiplication by drawing the first number above the second):
     *     - You start out with the rightmost digit in the ones place of the bottom number (analogous to b)
     *     - Then you multiply that number across the top number (analogous to a), and keep track of that place holders result to add at the end
     *     - Then you move left to the next place value for the bottom number (essentially shifting the bottom number (b) to the right, analogous to step 5), 
     *     - add a trailing 0 to the next round's multiplication result because you increased the place value (essentially shifting the top number (a) to the left, analogous to step 3),
     *     - and finally repeat the same steps
     *     - Then you add all the intermediate results of each place value to calculate the final result (analogous to step 1)
     * Except in instead of being in base-10, we are working within Galois field meaning "addition," "multiplication," and "moving place values" are done slightly differently,
     * along with the fact that we are working modulo P(x) and must reduce the result along the way  
     */

    uint8_t p = 0; // The product

    for (int i = 0; i < 8; i++) {
        if ((b & 0x01) == 0x01) {
            p ^= a;
        }
        uint8_t high_bit = (a & 0x80);
        a <<= 1;
        if (high_bit == 0x80) {
            a ^= 0x1b;
        }
        b >>= 1;
    }

    return p;
}

/**
 * Computes Galois field multiplication on the two inputs by using a lookup table
 * https://www.samiam.org/galois.html
 * @param a the multiplicand
 * @param b the multiplier
 * @returns the result of a * b within GF(2^8)
 */
uint8_t lookup_galois_mult(uint8_t a, uint8_t b) {
    return antilog_table[ (log_table[a] + log_table[b]) % 255 ];
    // Ideally there would be more logic here to make this run in constant speed to protect from timing attacks
}


/******************************
*** BYTE SUBSTITUTION LAYER ***
******************************/
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
 * Performs the MixColumn function on a single column of the state
 * This does the matrix multiplication of C[4][1] = MixColumn_Matrix[4][4] * Column[4][1]
 * @param column the column to mix
 */
void mix_column(uint8_t *column) {
    // Perform
    uint8_t C[4] = {0};
    for (int col = 0; col < 4; col++) { // For each row within the mixcolumn_matrix
        for (int i = 0; i < 4; i++) { // For each element within the working row
            C[col] ^= compute_galois_mult(mixcolumn_matrix[i + 4*col], column[i]);
            // C[col] ^= lookup_galois_mult(mixcolumn_matrix[i + 4*col], column[i]);
        }
    }

    // Replace the old column with the new column
    memcpy(column, C, 4);
}

/**
 * Performs the MixColumns sublayer on the current state
 * This is the primary function that introduces diffusion into the cipher, since every input byte influences 4 output bytes
 * @param state the current 128-bit state to mix
 */
void mix_columns(uint8_t *state) {
    for (int col = 0; col < 4; col++) {
        // Treat each column as a vector of size 4 and multiply it by the constant matrix
        uint8_t col_vect[4] = {state[0 + 4*col], state[1 + 4*col], state[2 + 4*col], state[3 + 4*col]};

        // Mix the column
        mix_column(col_vect);
        
        // Copy the results back into the state
        for (int i = 0; i < 4; i++) {
            state[i + 4*col] = col_vect[i];
        }
    }
}


/*************************
*** KEY ADDITION LAYER ***
*************************/
/**
 * Adds the current round's key (subkey) to the state
 * @param state the current 128-bit state to add the key to
 * @param subkey the 128-bit round key (subkey) to be added to the state
 */
void add_key(uint8_t *state, uint8_t *subkey) {
    // XOR is the same as addition in GF(2)
    for (int i = 0; i < 128/8; i++) {
        state[i] ^= subkey[i];
    }
}


/*******************
*** KEY SCHEDULE ***
*******************/
/**
 * Obtains the round coefficient to use for the provided key schedule round (NOT the AES round)
 * @param round_num the current key schedule round number, should be 1 or greater
 * @returns the 8-bit round coefficient
 */
uint8_t get_round_coefficient(uint8_t round_num) {
    /**
     * This is computed as coeff[i] = x^i in GF(2^8)
     *     coeff_1 = 0000 0001
     *     coeff_2 = 0000 0010
     *     coeff_3 = 0000 0100
     *     ...
     *     coeff_8 = 0001 1011
     */

    uint8_t coeff = 1; // Start at 0000 0001
    
    // Shift left for each round after 1
    // Reduce the polynomial mod P(x) if it extends past x^7 (recall AES's P(x) = x^8 + x^4 + x^3 + x + 1 = 0001 1011 = 0x1b)
    for (int i = 0; i < round_num - 1; i++) {
        uint8_t high_bit = (coeff & 0x80);
        coeff <<= 1;
        if (high_bit == 0x80) {
            coeff ^= 0x1b;
        }
    }

    return coeff;
}

/**
 * Performs the g function during the key schedule
 * @param word the input 32-bit word
 * @param round_num the current KEY SCHEDULE round number, should 1 or greater
 * @returns the resulting 32-bit word of the g function
 */
uint32_t g_function(uint32_t word, uint8_t round_num) {
    // Rotate the word bytes
    word = (word << 8) | (word >> 24);

    // Perform byte-wise substitution with S-box
    uint32_t output = 0;
    for (int i = 0; i < 4; i++) {
        output <<= 4;
        output |= sbox[(word >> (24 - 8*i)) & 0x000000FF];
    }

    // Add the round coefficient
    output ^= get_round_coefficient(round_num) << 24;

    return output;
}

/**
 * Performs the h function during the 256-bit key schedule
 * @param word the input 32-bit word
 * @returns the resulting 32-bit word of the h function
 */
uint32_t h_function(uint32_t word) {
    // Perform byte-wise substitution with S-box
    uint32_t output = 0;
    for (int i = 0; i < 4; i++) {
        output <<= 4;
        output |= sbox[(word >> (24 - 8*i)) & 0x000000FF];
    }
    return output;
}

uint8_t* generate_round_keys(uint8_t *key) {
    // The key schedule is word-oriented (1 word = 32 bits)
    uint8_t NUM_WORDS = (NUMROUNDS + 1) * 4;
    uint8_t WORDS_PER_ROUND = (KEYSIZE / 32);

    // All subkeys are stored in a key expansion array W consisting of words
    uint32_t *W = calloc(NUM_WORDS, sizeof(uint32_t));

    // The first subkey is the AES key
    memcpy(W, key, KEYSIZE / 8);

    // !!! If the subkey size and main keysize are NOT the same, the number of key generation rounds does NOT match the number of AES rounds !!!
    uint8_t NUM_KEYGEN_ROUNDS = (NUM_WORDS / WORDS_PER_ROUND) + ((NUM_WORDS % WORDS_PER_ROUND) > 0); // The last round does not always generate the same number of words as the others
    for (int i = 1; i < NUM_KEYGEN_ROUNDS; i++) {
        // Calculate the leftmost word
        W[WORDS_PER_ROUND * i] = W[WORDS_PER_ROUND * (i - 1)] ^ g_function(W[(WORDS_PER_ROUND * i) - 1], i);

        // Calculate the remaining words
        // NOTE: last subkey round will ALWAYS generate 4 words, so need the second condition to exit early
        //       AKA: loop until (all the words for the subkey round have been generated) OR (all of the subkey words have been generated)
        for (int j = 1; j < WORDS_PER_ROUND && (WORDS_PER_ROUND * i + j) < NUM_WORDS; j++) {
            if (j == 4 && KEYSIZE == 256) {
                W[WORDS_PER_ROUND * i + j] = h_function(W[WORDS_PER_ROUND * i + j - 1]) ^ W[WORDS_PER_ROUND * (i - 1) + j];
            }
            else {
                W[WORDS_PER_ROUND * i + j] = W[WORDS_PER_ROUND * i + j - 1] ^ W[WORDS_PER_ROUND * (i - 1) + j];
            }
        }
    }

    // Return the word array at a byte array for ease of use later
    return (uint8_t*)W;
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
    mix_columns(plaintext);
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