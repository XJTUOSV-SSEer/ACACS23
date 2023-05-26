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
#include <she.hpp>

using she::ParameterSet;
using she::PrivateKey;



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

//关键字w对应状态表ST中的一个entry
typedef struct ST1_value{
    int h_w_len; //multiset hash值长度
    int st_w_len; //状态st长度
    int c_w; //计数器值
    unsigned char* h_w; //multiset hash值
    unsigned char* st_w; //状态st
}ST1_value;


//ID_u对应状态表ST中的一个entry
typedef struct ST2_value{
    int h_u_len; //multiset hash值长度
    int st_u_len; //状态st长度
    int c_u; //计数器值
    unsigned char* h_u; //multiset hash值
    unsigned char* st_u; //状态st
}ST2_value;

//关键字w对应关键字索引ST中的一个entry
typedef struct I1_value{
    //unsigned char* e_w;
    //int e_w_len;
    int C_st_w_len; //C的密文长度
    unsigned char* C_st_w; //密文C
    she::EncryptedArray e_w; //密文e_w
}I1_value;

typedef struct I1_value_Compressed{
    //unsigned char* e_w;
    //int e_w_len;
    int C_st_w_len;
    unsigned char* C_st_w;
    she::CompressedCiphertext e_w;
}I1_value_Compressed;


//关键字w对应关键字索引ST中的一个entry
typedef struct I2_value{
    //unsigned char* e_u;
    int e_u_len; //密文e_w长度
    she::EncryptedArray e_u;//密文e_w
}I2_value;

typedef struct I2_value_Compressed{
    //unsigned char* e_u;
    int e_u_len;
    she::CompressedCiphertext e_u;
}I2_value_Compressed;

// typedef struct T_w_value{
//     int h_w_len;
//     unsigned char* h_w;
// }T_w_value;

typedef struct T_w_value{
    std::string decimalHash;
}T_w_value;

// typedef struct T_u_value{
//     unsigned char* h_u;
//     int h_u_len;
// }T_u_value;

typedef struct T_u_value{
    std::string decimalHash;
}T_u_value;


//search token 搜索令牌
typedef struct search_token{
    unsigned char* K_w; //k_w
    int K_w_length; //k_w长度
    unsigned char* K_u; //k_u
    int K_u_length; //k_w长度
    unsigned char* st_w; //st_w
    int st_w_length; //st_w长度
    unsigned char* st_u; //st_u
    int st_u_length; //st_u长度
    int c_w; //w计数器

    std::string h_w; //w对应的多集合哈希值
    std::string h_u; //ID_u对应的多集合哈希值

    char* w; //搜索关键字
    int w_len; //搜索关键字的长度
    char* id_u; //用户ID_u
    int id_u_len; //ID_u长度
}search_token;


typedef struct serverSearchRes{
    she::EncryptedArray Sum_e_w; //w的密文搜索结果
    she::EncryptedArray e_u; //ID_u的密文搜索结果
    std::string w; //关键字w
    std::string id_u; //ID_u
}serverSearchRes;

typedef struct decRes{
    std::vector<bool> bs_w;
    std::vector<bool> bs_u; 
}decRes;


#endif
