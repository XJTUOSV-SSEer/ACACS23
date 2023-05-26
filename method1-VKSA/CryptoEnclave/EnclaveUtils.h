#ifndef ENCLAVE_UTILS_H
#define ENCLAVE_UTILS_H

#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <iterator>
#include <vector>
#include <cstring>
#include "../common/data_type_enclave.h"


void printf( const char *fmt, ...);
void print_bytes(uint8_t *ptr, uint32_t len);
int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len);
void clear(uint8_t *dest, uint32_t len);
std::vector<std::string>  wordTokenize(char *content,int content_length);

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext, size_t ciphertext_len);
void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len);
int hash_SHA128(const void *key, const void *msg, int msg_len, void *value);
int hash_SHA128_key(const void *key, int key_len, const void *msg, int msg_len, void *value);
int hash_SHA256(const void *msg,int msg_len,void* value);
int hash_SHA256(const void *key,int key_len,const void* p,int p_len,void* value);
void Hashxor(unsigned char* hash1,unsigned char* hash2,int len,unsigned char* res);
void Hashand(unsigned char* hash1,unsigned char* hash2,int len,unsigned char* res);
void getMultiHash(std::vector<bool> bitmap,unsigned char* res,unsigned char* K,int K_len);
std::vector<bool> bitmap_transfer(unsigned char* bs,int bs_len);
std::string charToString(char* c,int len);
std::string unsignedcharToString(unsigned char* uc,int len);
bool unsignedcharCmp(unsigned char* uc1,unsigned char* uc2,int len);


//improved
//void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, entryKey *k );
//void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, entryValue *v);
//void prf_Dec_Improve(const void *key,const void *ciphertext,size_t ciphertext_len, entryValue *value );

#endif
