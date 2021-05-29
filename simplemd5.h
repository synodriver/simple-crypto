#ifndef _SIMPLE_MD5_H_
#define _SIMPLE_MD5_H_
#include <stdio.h>
#include <stdint.h>
//return 128bit(16bytes) digest
uint8_t* md5(const uint8_t *data, size_t data_len);
#endif