#if defined(AES_STANDALONE)

#ifndef aes_h
#define aes_h

#include <stdint.h>

typedef uint8_t state_t[4][4];

void aes_encrypt(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void aes_decrypt(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
    
#endif // aes_h

#endif // AES_STANDALONE
