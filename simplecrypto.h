#ifndef _SIMPLECRYPTO_H_
#define _SIMPLECRYPTO_H_
#include <stdio.h>
#include <stdint.h>

// ---------------MD5 area---------------

// return 128bit(16bytes) digest
uint8_t* md5(const uint8_t *data, size_t data_len);

// ---------------MD5 area---------------


// ---------------TEA area---------------

typedef uint32_t TEA;
struct TEADAT {
    int64_t len;
    uint8_t* data;
    void* ptr; // free() must use this val
};
typedef struct TEADAT TEADAT;

TEADAT* tea_encrypt_qq(const TEA t[4], const TEADAT* src);
TEADAT* tea_encrypt(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
TEADAT* tea_encrypt_native_endian(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
TEADAT* tea_decrypt_qq(const TEA t[4], const TEADAT* src);
TEADAT* tea_decrypt(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
TEADAT* tea_decrypt_native_endian(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);

// ---------------TEA area---------------

#endif