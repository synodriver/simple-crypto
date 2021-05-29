# simple-md5-lib

Simple C lib of the MD5 algorithm

# Install

```bash
git clone https://github.com/fumiama/simple-md5-lib.git
cd simple-md5-lib
mkdir build
cd build
cmake ..
make
make install
```

# Usage

1. Include `simplemd5.h` in your c program.
```c
#include <simplemd5.h>
```
2. Call `md5` function. Don't forget to `free` the returned digest.
```c
uint8_t* md5(const uint8_t *data, size_t data_len);
```