#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


/*******************
*** KEY SCHEDULE ***
*******************/
/**
 * Initialize the permutation in the S vector
 * @param key the secret key 
 * @param key_length the length of the secret key in BYTES
 * @param S where the S vector will be outputted
 */
void key_init(uint8_t *key, uint8_t key_len, uint8_t *S) {
    // Initialize S to identity matrix
    for (int i = 0; i < 256; i++) {
        S[i] = i;
    }

    // Process the key schedule
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        
        // Swap S[i] and S[j]
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}


/**********
*** RC4 ***
**********/
/**
 * Performs the Pseudo Randmon Generation Algorithm (PRGA) of the RC4 algorithm
 * @param input the text to encrypt/decrypt
 * @param len the length of the input in BYTES
 * @param key the secret key being used
 * @param key_len the length of the secret key in BYTES
 * @param output where the resulting ciphertext/plaintext will be outputted
 */
void rc4(uint8_t *input, uint8_t len, uint8_t *key, uint8_t key_len, uint8_t *output) {
    uint8_t S[256] = {0};
    key_init(key, key_len, S);

    uint8_t i = 0;
    uint8_t j = 0;

    for (int l = 0; l < len; l++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        // Swap S[i] and S[j]
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        // Get the current keystream byte to use
        uint8_t t = (S[i] + S[j]) % 256;
        uint8_t k = S[t];

        // Apply the cipher to the next byte
        output[l] = input[l] ^ k;
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
    uint8_t key[] = "Key";
    uint8_t key_len = 3;

    uint8_t *plaintext = "Plaintext";
    uint8_t len = 9;

    uint8_t ciphertext[len];
    uint8_t decrypted_plaintext[len];

    // Encrypt
    rc4(plaintext, len, key, key_len, ciphertext);

    // Decrypt
    rc4(ciphertext, len, key, key_len, decrypted_plaintext);
    
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