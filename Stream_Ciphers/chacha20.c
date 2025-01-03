#include <stdio.h>
#include <stdint.h>
#include <string.h>


#define KEY_SIZE_BITS 256 // Can be 256 or 128
#define NUM_ROUNDS 20 // Can be 20, 12, or 8


/****************************
*** INNER ROUND FUNCTIONS ***
****************************/
/**
 * Rotation to the left (ROTL), which rotates the given value by n bytes
 * @param value 32-bit word to rotate
 * @param shift integer value for number of bits to rotate
 */
uint32_t ROTL(uint32_t value, int shift) {
    // Wrap the bits around back to the start when shifting
    return (value << shift) | (value >> (32 - shift));
}

/**
 * Quarter-Round (QR) function, which adds, rotates, and XORs (ARX) the 4 input words 
 * This is applied to a single column/diagonal of the state
 * Since there are 4 columns/diagonals in total, a single call to this funciton is a "quarter of a round"
 * Applying it to each column/diagonal, would then be a "round"
 * @param a 32-bit word
 * @param b 32-bit word
 * @param c 32-bit word
 * @param d 32-bit word
 */
void QR(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a = *a + *b;
    *d = ROTL(*d ^ *a, 16);
    *c = *c + *d;
    *b = ROTL(*b ^ *c, 12);
    *a = *a + *b;
    *d = ROTL(*d ^ *a, 8);
    *c = *c + *d;
    *b = ROTL(*b ^ *c, 7);
}

/**
 * Odd number round of the ChaCha20 cipher
 * Operates on the columns of the ChaCha20 state matrix
 * @param state the 4x4 matrix containing the 16 32-bit state values
 */
void column_round(uint32_t *state) {
    QR(&state[0], &state[4], &state[8],  &state[12]);
    QR(&state[1], &state[5], &state[9],  &state[13]);
    QR(&state[2], &state[6], &state[10], &state[14]);
    QR(&state[3], &state[7], &state[11], &state[15]);
}

/**
 * Even number round of the ChaCha20 cipher
 * Operates on the diagonals of the ChaCha20 state matrix
 * @param state the 4x4 matrix containing the 16 32-bit state values
 */
void diagonal_round(uint32_t *state) {
    QR(&state[0], &state[5], &state[10], &state[15]);
    QR(&state[1], &state[6], &state[11], &state[12]);
    QR(&state[2], &state[7], &state[8],  &state[13]);
    QR(&state[3], &state[4], &state[9],  &state[14]);
}

/**
 * Performs a two rounds (double round) of the ChaCha20 cipher
 * The first (odd) round is on the columns, the second (even) round is on the diagonals
 * @param state the 4x4 matrix containing the 16 32-bit state values
 */
void double_round(uint32_t *state) {
    column_round(state);
    diagonal_round(state);
}


/**********************************
*** HIGH LEVEL CIPHER FUNCTIONS ***
**********************************/
/**
 * Sets up the internal state of the cipher for the given key, nonce, and counter/position
 * Also might be refered to as the 'key expansion' function
 * @param key 256-bit or 128-bit key (same across all blocks)
 * @param nonce 64-bit (8-byte) nonce (same across all blocks)
 * @param position 64-bit (8-byte) integer for the current block number/position (allows you to skip around to different parts of text, and do computations in parallel)
 * @param state OUTPUT 16 32-bit words for the internal state of the cipher for the given key, nonce, and position
 */
void chacha20_init(uint32_t *key, uint32_t *nonce, uint32_t *position, uint32_t *state) {
    // Nothing-up-my-sleve number to protect against 0s in the key or nonce
    uint32_t *constants = (KEY_SIZE_BITS == 256) ? "expand 32-byte k" : "expand 16-byte k";

    state[0] = constants[0]; // First 32 bits of the constant value
    state[1] = constants[1]; 
    state[2] = constants[2]; 
    state[3] = constants[3]; 

    state[4] = key[0]; // First 32 bits of the key
    state[5] = key[1]; 
    state[6] = key[2];
    state[7] = key[3];
    
    state[8] = (KEY_SIZE_BITS == 256) ? key[4] : key[0]; 
    state[9] = (KEY_SIZE_BITS == 256) ? key[5] : key[1]; 
    state[10] = (KEY_SIZE_BITS == 256) ? key[6] : key[2];
    state[11] = (KEY_SIZE_BITS == 256) ? key[7] : key[3];

    state[12] = position[0]; // Lower 32 bits of the block counter/position
    state[13] = position[1]; // Upper 32 bits
    state[14] = nonce[0]; // Lower 32 bits of the nonce
    state[15] = nonce[1]; // Upper 32 bits
}

/**
 * Gets the keystream for a given block for the ChaCha20 cipher
 * A "block" is another name for the ChaCha20 4x4 state matrix (which is shaped like a block)
 * This function might be refered to as a hash function, since it is extremely similar to a hash as it is mixing around the data
 * @param state the internal state of the ChaCha20 cipher, should already be initialized with the proper key, nonce, and have the correct block number/position set 
 * @param keystream OUTPUT the 512-bit (16 32-bit words) output keystream for the given block position
 */
void chacha20_block(uint32_t *state, uint32_t *keystream) {
    // Copy the current state to a working variable
    uint32_t mixed_block[16];
    for (int i = 0; i < 16; i++) {
        mixed_block[i] = state[i];
    }

    // Perform the actual rounds on the state to mix it up
    for (int i = 0; i < NUM_ROUNDS / 2; i++) {
        double_round(mixed_block);
    }

    // Set the keystream to the addition of the original state and the recently mixed state
    for (int i = 0; i < 16; i++) {
        keystream[i] = mixed_block[i] + state[i];
    }
}

/**
 * Applies the ChaCha20 cipher to a given input text using the provided key and nonce (this same function does encryption and decryption)
 * @param input the input to apply the cipher to, will be the plaintext if doing encryption and be the ciphertext if doing decryption
 * @param len length of the input/output in BYTES
 * @param key the 256-bit or 128-bit symmetric key being used for the cipher
 * @param nonce 64-bit nonce being used for the cipher
 * @param output OUTPUT the output of the cipher, should be the same size as the input, will be the ciphertext if doing encryption and be the plaintext if doing decryption
 */
void chacha20(uint8_t *input, int len, 
             uint32_t *key, uint32_t *nonce, 
             uint8_t *output) {
    // Internal variables for the cipher
    uint32_t state[16]; // The 4x4 matrix holding the variables that define the cipher (mainly the key and nonce, plus a position value for where in the cipher we are, plus constant values to fill the rest)
    uint8_t keystream[64]; // The keystream generated by the cipher use to encrypt/decrypt
                           // My implementation only keeps track of one block's worth of keystream at a time (512-bit) for simplicity
                           // However, this could easily be split up where each block's keystream be calculated in parallel
    
    // Expand the key and create the initial state
    uint64_t block_num = 0; // Start at block 0
    chacha20_init((uint32_t*)key, (uint32_t*)nonce, (uint32_t*)(&block_num), state);

    // Loop through the input message, generate the keystream for the current block, and XOR it with the current input block to get the output
    // This cipher works in 512-bit (64-byte) blocks, because that is the size of the keystream generated for each block
    // However, it is still a stream cipher since each bit is encrypted individually, it just so happens that the cipher generates the keystream in chunks/blocks
    for (int block_pos = 0; block_pos < len; block_pos += 64) { // For each 512-bit (64-byte) block in the input, apply the cipher
        // Generate the 512-bit keystream for the current block
        chacha20_block(state, (uint32_t*)keystream);

        // Apply the cipher to the input text
        for (int i = 0; (i < 64) && ((block_pos + i) < len); i++) { // Apply bits until either the keystream is used up, OR we get to the end of the input
            output[block_pos + i] = input[block_pos + i] ^ keystream[i];
        }
        
        // Increment the block position counter (which is stored in the state)
        state[8] = (state[8] + 1) & 0xFFFFFFFF; // Adds 1 to the lower 32 bits of the block number (the "& 0xFFFFFFFF" essential performs a modulo 2^32)
        if (state[8] == 0) { // Handle overflow
            state[9] = (state[9] + 1) & 0xFFFFFFFF; // Upper 32 bits of the block number 
        }
    }
}


/**************
*** TESTING ***
**************/
void print_hex(unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int main() {
    // Set test variables for the cipher
    uint8_t key[32] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    uint8_t nonce[8] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a
    };

    uint8_t *plaintext = "This is my test chacha20 input text that is much much longer and should use up two full blocks of keystream plus a few extra bits for good measure!";
    int len = 147;
    uint8_t ciphertext[len];
    uint8_t decrypted_plaintext[len];

    // Encrypt
    chacha20(plaintext, len, (uint32_t*)key, (uint32_t*)nonce, ciphertext);

    // Decrypt
    chacha20(ciphertext, len, (uint32_t*)key, (uint32_t*)nonce, decrypted_plaintext);
    
    // Print the results
    printf(plaintext);
    printf("\n\n\r");
    print_hex(ciphertext, len);
    printf("\n\r");
    printf(decrypted_plaintext);
    printf("\n\r");

    // Sanity check the results
    if (memcmp(plaintext, ciphertext, len) == 0) {
        printf("ERROR: Plaintext and ciphertext ARE the same!");
    }
    if (memcmp(plaintext, decrypted_plaintext, len) != 0) {
        printf("ERROR: Plaintext and decrypted_plaintext are NOT the same!");
    }
    
    return 0;
}

