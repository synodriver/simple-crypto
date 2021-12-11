# simple-crypto

Simple C lib of the MD5 & TEA algorithm

# Install

```bash
git clone https://github.com/fumiama/simple-crypto.git
cd simple-crypto
mkdir build
cd build
cmake ..
make
make install
```

# Usage

1. Include `simplecrypto.h` in your c program.
```c
#include <simplecrypto.h>
```
2. Call functions. Don't forget to `free` the returned digest.
```c
uint8_t* md5(const uint8_t *data, size_t data_len);

TEADAT* tea_encrypt_qq(const TEA t[4], const TEADAT* src);
TEADAT* tea_encrypt(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
TEADAT* tea_encrypt_native_endian(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
TEADAT* tea_decrypt_qq(const TEA t[4], const TEADAT* src);
TEADAT* tea_decrypt(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
TEADAT* tea_decrypt_native_endian(const TEA t[4], const uint32_t sumtable[0x10], const TEADAT* src);
```