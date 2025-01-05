#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/****************
*** CONSTANTS ***
****************/
/**
 * Trivium registers indices start counting at 1, so many functions in this program also start counting at 1
 * This makes for some non-traditional indexing, so be careful!
 * While not as standardized or regulated as other ciphers, Trivium has been standardized as a "lightweight cipher" in ISO/IEC 29192-3 (2012)
 */
#define NUM_REGS 288

#define LFSR_A_SIZE 93
#define LFSR_A_START 1
#define LFSR_A_FEEDBACK 69
#define LFSR_A_FEEDFORWARD 66
#define LFSR_A_AND1 91
#define LFSR_A_AND2 92
#define LFSR_A_END 93

#define LFSR_B_SIZE 84
#define LFSR_B_START (LFSR_A_END + 1)
#define LFSR_B_FEEDBACK (LFSR_B_START + 78 - 1)
#define LFSR_B_FEEDFORWARD (LFSR_B_START + 69 - 1)
#define LFSR_B_AND1 (LFSR_B_START + 82 - 1)
#define LFSR_B_AND2 (LFSR_B_START + 83 - 1)
#define LFSR_B_END (LFSR_B_START + LFSR_B_SIZE - 1)

#define LFSR_C_SIZE 111
#define LFSR_C_START (LFSR_B_END + 1)
#define LFSR_C_FEEDBACK (LFSR_C_START + 87 - 1)
#define LFSR_C_FEEDFORWARD (LFSR_C_START + 66 - 1)
#define LFSR_C_AND1 (LFSR_C_START + 109 - 1)
#define LFSR_C_AND2 (LFSR_C_START + 110 - 1)
#define LFSR_C_END (LFSR_C_START + LFSR_C_SIZE - 1)


/***********************
*** HELPER FUNCTIONS ***
***********************/
/**
 * Gets the value of the bit at position bit_pos
 * @param ptr the pointer to the first byte of memory to start the access from
 * @param bit_pos the position of the bit to get the value of (1 = LSB)
 * @returns an integer (0 or 1) of the value of the bit
 */
int get_bit(uint8_t *ptr, int bit_pos) {
    return (ptr[(bit_pos - 1) / 8] >> ((bit_pos - 1) % 8)) & 0x1;
}

/**
 * Sets the value of the bit in the pointer located at position bit_pos
 * @param ptr the pointer to the first byte of memory to start the access from
 * @param bit_pos the position of the bit to set the value of (LSB = 1)
 * @param val the value to set the bit to (0 or 1)
 */
void set_bit(uint8_t *ptr, int bit_pos, int val) {
    if (val == 1) {
        ptr[(bit_pos - 1) / 8] |= (1 << ((bit_pos - 1) % 8));
    }
    else {
        ptr[(bit_pos - 1) / 8] &= (~(1 << ((bit_pos - 1) % 8)));
    }
}

void print_state(uint8_t *state) {
    printf("REGISTERS = \n\r");
    for (int i = 1; i <= NUM_REGS; i++) {
        printf("%d", get_bit(state, i));

        if (i == (LFSR_B_START - 1) || i == (LFSR_C_START -1)) {
            printf("\n\r");
        }
    }
    printf("\n\r");
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
    memset(state, 0, 36); // 36 bytes = 288 bits

    // Load the key into LFSR A one bit at a time
    for (int i = 0; i < 80; i++) {
        int key_bit = get_bit(&key[i / 8], (8 - (i % 8))); // Byte is in reverse order
        set_bit(state, LFSR_A_START + i, key_bit);
    }

    // Load the IV into LFSR B one bit at a time
    for (int i = 0; i < 80; i++) {
        int iv_bit = get_bit(&iv[i / 8], (8 - (i % 8))); // Byte is in reverse order
        set_bit(state, LFSR_B_START + i, iv_bit);
    }

    // Set the last 3 bits of LFSR C to be 1
    set_bit(state, LFSR_C_END, 1);
    set_bit(state, LFSR_C_END - 1, 1);
    set_bit(state, LFSR_C_END - 2, 1);
}

/**
 * Generate a single bit of keystream
 * Essentially "clocks" the cipher, updating the states of all the registers and generating a single bit of output
 * @param state the 288-bit Trivium register state
 * @returns an integer (0 or 1) of generated keystream bit
 */
int trivium_generate_bit(uint8_t *state) {
    // Calculate the intermediary LFSR output bits
    int a_out = get_bit(state, LFSR_A_END) ^ get_bit(state, LFSR_A_FEEDFORWARD);
    int b_out = get_bit(state, LFSR_B_END) ^ get_bit(state, LFSR_B_FEEDFORWARD);
    int c_out = get_bit(state, LFSR_C_END) ^ get_bit(state, LFSR_C_FEEDFORWARD);

    // Calculate the new values to be fed back into the LFSRs
    uint8_t b_in = a_out ^ (get_bit(state, LFSR_A_AND1) & get_bit(state, LFSR_A_AND2)) ^ get_bit(state, LFSR_B_FEEDBACK);
    uint8_t c_in = b_out ^ (get_bit(state, LFSR_B_AND1) & get_bit(state, LFSR_B_AND2)) ^ get_bit(state, LFSR_C_FEEDBACK);
    uint8_t a_in = c_out ^ (get_bit(state, LFSR_C_AND1) & get_bit(state, LFSR_C_AND2)) ^ get_bit(state, LFSR_A_FEEDBACK);
    
    // printf("LFSR_A_FEEDFORWARD = %d\n\r", get_bit(state, LFSR_A_FEEDFORWARD));
    // printf("LFSR_A_END = %d\n\r", get_bit(state, LFSR_A_END));
    // printf("a_out = %d\n\n\r", a_out);

    // printf("LFSR_B_FEEDFORWARD = %d\n\r", get_bit(state, LFSR_B_FEEDFORWARD));
    // printf("LFSR_B_END = %d\n\r", get_bit(state, LFSR_B_END));
    // printf("b_out = %d\n\n\r", b_out);

    // printf("LFSR_C_FEEDFORWARD = %d\n\r", get_bit(state, LFSR_C_FEEDFORWARD));
    // printf("LFSR_C_END = %d\n\r", get_bit(state, LFSR_C_END));
    // printf("c_out = %d\n\n\r", c_out);

    // printf("LFSR_A_AND1 = %d\n\r", get_bit(state, LFSR_A_AND1));
    // printf("LFSR_A_AND2 = %d\n\r", get_bit(state, LFSR_A_AND2));
    // printf("LFSR_B_FEEDBACK = %d\n\r", get_bit(state, LFSR_B_FEEDBACK));
    // printf("b_in = %d\n\n\r", b_in);
    
    // printf("LFSR_B_AND1 = %d\n\r", get_bit(state, LFSR_B_AND1));
    // printf("LFSR_B_AND2 = %d\n\r", get_bit(state, LFSR_B_AND2));
    // printf("LFSR_C_FEEDBACK = %d\n\r", get_bit(state, LFSR_C_FEEDBACK));
    // printf("c_in = %d\n\n\r", c_in);
    
    // printf("LFSR_C_AND1 = %d\n\r", get_bit(state, LFSR_C_AND1));
    // printf("LFSR_C_AND2 = %d\n\r", get_bit(state, LFSR_C_AND2));
    // printf("LFSR_A_FEEDBACK = %d\n\r", get_bit(state, LFSR_A_FEEDBACK));
    // printf("a_in = %d\n\n\r", a_in);

    // printf("Generated bit : %d\n\n\r", (a_out ^ b_out ^ c_out));

    // Update the LFSRs
    // Shift all values in LFSR A
    for (int i = LFSR_A_END; i > LFSR_A_START; i--) {
        set_bit(state, i, get_bit(state, i - 1));
    }
    set_bit(state, LFSR_A_START, a_in); // Set the input bit

    // Shift all values in LFSR B
    for (int i = LFSR_B_END; i > LFSR_B_START; i--) {
        set_bit(state, i, get_bit(state, i - 1));
    }
    set_bit(state, LFSR_B_START, b_in); // Set the input bit

    // Shift all values in LFSR C
    for (int i = LFSR_C_END; i > LFSR_C_START; i--) {
        set_bit(state, i, get_bit(state, i - 1));
    }
    set_bit(state, LFSR_C_START, c_in); // Set the input bit

    // Calculate the keystream bit
    return a_out ^ b_out ^ c_out;
}

/**
 * Generate a byte of keystream to make it more convenient to encrypt/decrypt messages
 * @param state the 288-bit Trivium register state
 * @returns a byte of keystream material
 */
int trivium_generate_byte(uint8_t *state) {
    uint8_t keystream_byte = 0x00;
    for (int i = 1; i <= 8; i++) {
        set_bit(&keystream_byte, i, trivium_generate_bit(state));
    }
    // printf("Generated byte: %02x\n\n\r", keystream_byte);

    return keystream_byte;
}

/**
 * "Warms up" the cipher by clocking it 4*288 = 1152 times
 * This will properly randomize the internal state such that attackers cannot compute the key from the keystream
 * @param state the 288-bit Trivium register state
 */
void trivium_warm_up(uint8_t *state) {
    for (int i = 0; i < 4*288; i++) {
        trivium_generate_bit(state); // Ignore the output
    }
}

/**
 * Apply the Trivium cipher to an input text using the provided key and IV (this same function does encryption and decryption)
 * @param input the input text to apply the cipher to
 * @param len the length of the input/output text in BYTES
 * @param key the 80-bit key to use with the cipher
 * @param iv the 80-bit initialization vector (IV) to use with the cipher
 * @param output OUTPUT the output result of the cipher, will be the same length as the input (maximum of 2^64 bits)
 */
void trivium(uint8_t *input, int len, 
             uint8_t *key, uint8_t *iv,
             uint8_t *output) {
    
    // The internal cipher variables
    uint8_t state[36]; // 36 bytes = 288 bits representing the circular combinations of the 3 LFSRs (93 + 84 + 111) 
    
    // Initialize the cipher
    trivium_init(key, iv, state);
    trivium_warm_up(state);

    // Loop through the input, encrypting/decrypting one byte at a time
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ trivium_generate_byte(state);
    }
}


/**************
*** TESTING ***
**************/
int main() {
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
    printf("plaintext = %s\n\r", plaintext);
    printf("ciphertext = %s\n\r", ciphertext);
    printf("decrypted_plaintext = %s\n\r", decrypted_plaintext);

    // Sanity check the results
    if (memcmp(plaintext, ciphertext, len) == 0) {
        printf("ERROR: Plaintext and ciphertext ARE the same!\n\r");
    }
    if (memcmp(plaintext, decrypted_plaintext, len) != 0) {
        printf("ERROR: Plaintext and decrypted_plaintext are NOT the same!\n\r");
    }

    return 0;
}