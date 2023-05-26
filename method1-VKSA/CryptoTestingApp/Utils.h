#ifndef UTILS_H
#define UTILS_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "openssl/sha.h"
#include <string.h>
#include <sstream>
#include <sys/stat.h>
//#include <she.hpp>
#include <boost/archive/text_oarchive.hpp> 
#include <boost/archive/text_iarchive.hpp> 

#include "../common/data_type.h"
#include <chrono>
 
void handleErrors(void);

void print_bytes(unsigned char *ptr, uint32_t len);

void test();
void printBitmap(std::vector<bool> bitmap);

int enc_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key,
                unsigned char *ciphertext);//加密

int dec_aes_gcm(unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key,
                unsigned char *plaintext);//解密

bool is_directory(const std::string& path);

int hash_sha256(unsigned char* message,size_t len,unsigned char* res);

void Hashxor(unsigned char* hash1,unsigned char* hash2,int len,unsigned char* res);

int hash256(unsigned char* K,int K_len,unsigned char* params,int p_len,unsigned char* res);

void getMultiHash(std::vector<bool> bitmap,unsigned char* res,unsigned char* K,int K_len);

she::EncryptedArray homomorAdd(unsigned char* e1,int e1_len ,unsigned char* e2,int e2_len);

she::CompressedCiphertext e_transfer(unsigned char* e);

unsigned char* e_transfer(she::EncryptedArray e,int& len);

bool isZero(unsigned char* input,int len);
std::string unsignedcharToString(unsigned char* uc,int len);
std::string charToString(char* c,int len);

unsigned char* bitmap_tranfer(std::vector<bool> bs);

std::vector<bool> bitmap_tranfer(unsigned char* bs,int bs_len);

uint64_t timeSinceEpochMillisec();



#endif