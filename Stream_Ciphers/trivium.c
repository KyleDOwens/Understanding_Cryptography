#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


// Define constants that indicate which bits within the LFSRs are used for what
#define STATE_BITS 288

#define lfsr_a_start 0
#define lfsr_a_feedback 68
#define lfsr_a_feedforward 65
#define lfsr_a_and1 90
#define lfsr_a_and2 91
#define lfsr_a_end 92

#define lfsr_b_start 93
#define lfsr_b_feedback (lfsr_b_start + 77)
#define lfsr_b_feedforward (lfsr_b_start + 68)
#define lfsr_b_and1 (lfsr_b_start + 81)
#define lfsr_b_and2 (lfsr_b_start + 82)
#define lfsr_b_end 176

#define lfsr_c_start (lfsr_b_start + 84)
#define lfsr_c_feedback (lfsr_c_start + 87)
#define lfsr_c_feedforward (lfsr_c_start + 65)
#define lfsr_c_and1 (lfsr_c_start + 108)
#define lfsr_c_and2 (lfsr_c_start + 109)
#define lfsr_c_end 287

void print_bits(unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < 8; j++) {
            printf("%d", !!((bytes[i] << j) & 0x80));
        }
    }
    printf("\n");
}
void print_bits_little_last(unsigned char *bytes, int len) {
    for (int i = len - 1; i >= 0; i--) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", !!((bytes[i] << j) & 0x80));
        }
    }
    printf("\n");
}

void print_hex(unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

void print_hex_no_space(unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void print_LFSR(uint8_t *state, char letter) {
    if (letter == 'A') {
        print_bits_little_last(&state[0], 93);
        print_hex_no_space(&state[lfsr_a_start], 93);
    }
    if (letter == 'B') {
        print_bits_little_last(&state[lfsr_b_start], 84);
        print_hex_no_space(&state[lfsr_b_start], 84);
    }
    if (letter == 'C') {
        print_bits_little_last(&state[lfsr_c_start], 111);
        print_hex_no_space(&state[lfsr_c_start], 111);
    }
}


/***********************
*** HELPER FUNCTIONS ***
***********************/
/**
 * Gets the value of the bit within pointer located at position bit_pos (0 or 1)
 * @param ptr the pointer to get the bit from 
 * @param bit_pos the position of the bit to get the value of (assumes you are accessing safe memory)
 * @returns an integer (0 or 1) of the value of the bit
 */
int get_bit(uint8_t *ptr, int bit_pos) {
    int ret = (ptr[bit_pos / 8] >> (bit_pos % 8)) & 0x1;
    return ret;
}

/**
 * Sets the value of the bit in the pointer located at position bit_pos
 * @param ptr the pointer to set the bit of
 * @param bit_pos the position of the bit to set the value of (assumes you are accessing safe memory)
 * @param val the value to set the bit to (0 or 1)
 */
void set_bit(uint8_t *ptr, int bit_pos, int val) {
    if (val == 1) {
        ptr[bit_pos / 8] |= (1 << (bit_pos % 8));
    }
    else {
        ptr[bit_pos / 8] &= ~(1 << bit_pos);
    }
}


/***********************************
*** HIGH LEVEL TRIVIUM FUNCTIONS ***
***********************************/
/**
 * Sets the initial state of the Trivium registers, depending on the key and IV
 * @param key the 80-bit key being used
 * @param iv the 80-bit initialization vector (IV) being used
 * @param state OUTPUT the initial 288-bit state of the registers 
 */
void trivium_init(uint8_t *key, uint8_t *iv, uint8_t *state) {
    memset(state, 0, STATE_BITS/8);

    // Load the key into LFSR A one bit at a time
    for (int i = 0; i < 80; i++) {
        int key_bit = (key[i / 8] >> (i % 8)) & 1;
        set_bit(state, lfsr_a_start + i, key_bit);
    }

    // Load the IV into LFSR B one bit at a time
    for (int i = 0; i < 80; i++) {
        int iv_bit = (iv[i / 8] >> (i % 8)) & 1;
        set_bit(state, lfsr_b_start + i, iv_bit);
    }

    // Set the last 3 bits of LFSR C to be 1
    set_bit(state, STATE_BITS - 1, 1);
    set_bit(state, STATE_BITS - 2, 1);
    set_bit(state, STATE_BITS - 3, 1);
}

/**
 * Generate a single bit of keystream
 * Essentially "clocks" the cipher, updating the states of all the registers and generating a single bit of output
 * @param state the 288-bit Trivium register state
 * @returns an integer (0 or 1) of generated keystream bit
 */
int trivium_generate_bit(uint8_t *state) {
    print_hex(state, STATE_BITS/8);

    printf("BEFORE\n\r");
    print_LFSR(state, 'A');

    // Calculate the intermediary LFSR output bits
    int a_out = get_bit(state, lfsr_a_end) ^ get_bit(state, lfsr_a_feedforward);
    int b_out = get_bit(state, lfsr_b_end) ^ get_bit(state, lfsr_b_feedforward);
    int c_out = get_bit(state, lfsr_c_end) ^ get_bit(state, lfsr_c_feedforward);

    // Calculate the new values to be fed back into the LFSRs
    uint8_t b_in = a_out ^ (get_bit(state, lfsr_a_and1) & get_bit(state, lfsr_a_and2)) ^ get_bit(state, lfsr_b_feedback);
    uint8_t c_in = b_out ^ (get_bit(state, lfsr_b_and1) & get_bit(state, lfsr_b_and2)) ^ get_bit(state, lfsr_c_feedback);
    uint8_t a_in = c_out ^ (get_bit(state, lfsr_c_and1) & get_bit(state, lfsr_c_and2)) ^ get_bit(state, lfsr_a_feedback);
    
    printf("a_in = %d\n\r", a_in);
    printf("b_in = %d\n\r", b_in);
    printf("c_in = %d\n\r", c_in);

    // Update the LFSRs
    // Shift all values in LFSR A
    for (int i = lfsr_a_end; i > 0; i--) {
        set_bit(state, i, get_bit(state, i - 1));
    }
    set_bit(state, lfsr_a_start, a_in); // Set the input bit

    printf("AFTER\n\r");
    print_LFSR(state, 'A');

    // Shift all values in LFSR B
    for (int i = lfsr_b_end; i > lfsr_a_end; i--) {
        set_bit(state, i, get_bit(state, i - 1));
    }
    set_bit(state, lfsr_b_start, b_in); // Set the input bit

    // Shift all values in LFSR C
    for (int i = lfsr_c_end; i > lfsr_b_end; i--) {
        set_bit(state, i, get_bit(state, i - 1));
    }
    set_bit(state, lfsr_c_start, c_in); // Set the input bit

    // Calculate the keystream bit
    printf("Generated bit : %d\n\n\r", (a_out ^ b_out ^ c_out));
    exit(2);
    return a_out ^ b_out ^ c_out;
}

/**
 * Generate a byte of keystream to make it more convenient to encrypt/decrypt messages
 * @param state the 288-bit Trivium register state
 * @returns a byte of keystream material
 */
int trivium_generate_byte(uint8_t *state) {
    uint8_t keystream_byte = 0;
    for (int i = 0; i < 8; i++) {
        set_bit(&keystream_byte, i, trivium_generate_bit(state));
    }
    printf("Generated byte: %02x\n\n\r", keystream_byte);
    exit(2);

    return keystream_byte;
}

/**
 * "Warms up" the cipher by clocking it 1152 times
 * This will properly randomize the internal state such that attackers cannot compute the key from the keystream
 * @param state the 288-bit Trivium register state
 */
void trivium_warm_up(uint8_t *state) {
    for (int i = 0; i < 0; i++) {
        trivium_generate_bit(state); // Ignore the output
    }

    print_hex(state, STATE_BITS/8);
    printf("WARM UP DONE\n\r-----------------------------------------------------\n\r");
}

/**
 * Apply the Trivium cipher to an input text using the provided key and IV (this same function does encryption and decryption)
 * @param input the input text to apply the cipher to
 * @param len the length of the input/output text in BYTES
 * @param key the key to use with the cipher
 * @param iv the initialization vector (IV) to use with the cipher
 * @param output OUTPUT the output result of the cipher, will be the same length as the input
 */
void trivium(uint8_t *input, int len, 
             uint8_t *key, uint8_t *iv,
             uint8_t *output) {
    
    // The internal cipher variables
    uint8_t state[STATE_BITS / 8]; // 288-bit value representing the circular combinations of the 3 LFSRs (93 + 84 + 111) 
    
    // Initialize the cipher
    trivium_init(key, iv, state);
    trivium_warm_up(state);

    // Loop through the input, encrypting one byte at a time
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ trivium_generate_byte(state);
    }
}

/**************
*** TESTING ***
**************/


void main() {
    // Set test variables for the cipher
    uint8_t key[10] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09
    };

    uint8_t iv[10] = {
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13
    };

    uint8_t *plaintext = "Hello, Trivium!";
    size_t len = 15;
    uint8_t ciphertext[len];
    uint8_t decrypted_plaintext[len];

    // Encrypt
    trivium(plaintext, len, key, iv, ciphertext);

    // Decrypt
    trivium(ciphertext, len, key, iv, decrypted_plaintext);

    // Print results
    printf(plaintext);
    printf("\n\n\r");
    printf(ciphertext);
    print_hex(ciphertext, len);
    printf("\n\r");
    printf(decrypted_plaintext);
    printf("\n\r");

    // Sanity check the results
    if (memcmp(plaintext, ciphertext, len) == 0) {
        printf("ERROR: Plaintext and ciphertext ARE the same!\n\r");
    }
    if (memcmp(plaintext, decrypted_plaintext, len) != 0) {
        printf("ERROR: Plaintext and decrypted_plaintext are NOT the same!\n\r");
    }

    return 0;
}