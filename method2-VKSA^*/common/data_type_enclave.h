#ifndef DATA_TYPE_H
#define DATA_TYPE_H

#include "config.h"
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <array>
#include <list>
#include <string>
#include <tuple>
#include <utility>
#include <unordered_map>



/* for all sources except OCALL/ECALL */

const std::string raw_doc_dir= "streaming/"; 

#define AESGCM_IV_SIZE 12//Question: AES加密算法需要的参数？补全长度？
static unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

#define AESGCM_MAC_SIZE 16//Question: AES加密算法需要的参数？补全长度？

#define MAX_FILE_LENGTH 10 

#define ENC_KEY_SIZE 16 // for AES128
#define ENTRY_VALUE_LEN 128 // 1024-bit

#define ENTRY_HASH_KEY_LEN_128 16 // for HMAC-SHA128- bit key
#define BUFLEN 10240 //buffer for enc + dec
#define RAND_LEN 64// 256 // 2048-bit

#define SHA_256_SIZE 32 // for SHA256

//消息
typedef struct
{
    size_t content_length;
    unsigned char content[RAND_LEN];
} rand_t; //used to export between ecall and ocall


//文件ID
typedef struct docIds {
    char *doc_id; 
    size_t id_length;  // length of the doc_id
} docId; 

// 密钥?
typedef struct entryKeys {
    char *content; 
    size_t content_length;  // length of the entry_value
} entryKey;

//明文
typedef struct entryValues {
    char *message; 
    size_t message_length;  // length of the entry_value
} entryValue;

typedef struct docContents{
    docId id;
    char* content;
    int content_length;
    //std::vector<std::string> wordList;
} docContent;



typedef std::pair<entryKey, entryValue> entry;//entry登记 ,作为密文

//st_w,c_w,h_w
typedef struct ST1_value{
    unsigned char* st_w;
    int st_w_len;
    int c_w;
    unsigned char* h_w;
    int h_w_len;
}ST1_value;

typedef struct ST2_value{
    unsigned char* st_u;
    int st_u_len;
    int c_u;
    unsigned char* h_u;
    int h_u_len;
}ST2_value;

typedef struct T_w_value{
    unsigned char* h_w;
    int h_w_len;
}T_w_value;

typedef struct T_u_value{
    unsigned char* h_u;
    int h_u_len;
}T_u_value;

typedef struct search_token{
    unsigned char* K_w;
    int K_w_length;
    unsigned char* K_u;
    int K_u_length;
    unsigned char* st_w;
    int st_w_length;
    unsigned char* st_u;
    int st_u_length;
    int c_w;
    int c_u;

    char* w;
    int w_len;
    char* id_u;
    int id_u_len;
}search_token;

#endif
