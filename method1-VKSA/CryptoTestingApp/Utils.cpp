#include "Utils.h"


#include <vector>
#include <iostream>
 
using std::string;
using std::vector;


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}



int enc_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key,
                unsigned char *ciphertext)
{
  
    unsigned char output[AESGCM_MAC_SIZE+ AESGCM_IV_SIZE + plaintext_len*2] = {0};
    memcpy(output+AESGCM_MAC_SIZE,gcm_iv,AESGCM_IV_SIZE);
    
    int ciphertext_len=0, final_len=0;
  
    EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_gcm(),key, gcm_iv);

    EVP_EncryptUpdate(ctx, output+ AESGCM_MAC_SIZE+ AESGCM_IV_SIZE, &ciphertext_len, plaintext, plaintext_len);
    EVP_EncryptFinal(ctx, output+ AESGCM_MAC_SIZE+ AESGCM_IV_SIZE + ciphertext_len, &final_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AESGCM_MAC_SIZE, output);
    EVP_CIPHER_CTX_free(ctx);

    ciphertext_len = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE + ciphertext_len + final_len;
    memcpy(ciphertext,output,ciphertext_len);
    
    return ciphertext_len;
    
}

int dec_aes_gcm(unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int plaintext_len=0, final_len=0;
    
    EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, gcm_iv);
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, 
                      ciphertext+AESGCM_MAC_SIZE+AESGCM_IV_SIZE, 
                      ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AESGCM_MAC_SIZE, ciphertext);
    EVP_DecryptFinal(ctx, plaintext + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len = plaintext_len + final_len;

    return plaintext_len;
}

void print_bytes(unsigned char *ptr, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    printf("%x ", *(ptr + i));
  }
  printf("\n");
}

bool is_directory(const std::string& path)
{
    struct stat sb;

    if (stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        return true;
    }
    return false;
}

//return the length of res
int hash_sha256(unsigned char* message,size_t len,unsigned char* res){
    SHA256_CTX* ctx = new SHA256_CTX();
    SHA256_Init(ctx);
    SHA256_Update(ctx,message,len);
    SHA256_Final(res,ctx);
    return 32;
    //printf("out of enclave:\n");
    //print_bytes(res,32);
}

void Hashxor(unsigned char* hash1,unsigned char* hash2,int len,unsigned char* res){
    for(int i=0;i<len;i++){
        res[i] = hash1[i] ^ hash2[i];
    }
}

int hash256(unsigned char* K,int K_len,unsigned char* params,int p_len,unsigned char* res){
    unsigned char* connect = (unsigned char*)malloc(K_len+p_len);
    memcpy(connect,K,K_len);
    memcpy(connect+ K_len,params,p_len);
    int res_length = hash_sha256(connect,K_len+p_len,res);
    free(connect);
    return res_length;
}

void getMultiHash(std::vector<bool> bitmap,unsigned char* res,unsigned char* K,int K_len){
    std::string input = unsignedcharToString(K,K_len);
    bool first = true;
    for(int i=0;i<bitmap.size();i++){
        if(bitmap[i] == 1){
            unsigned char* temp = (unsigned char*)malloc(SHA_256_SIZE);
            std::string hash_input = input + std::to_string(i);
            unsigned char* message = (unsigned char*)hash_input.c_str();
            hash_sha256(message,hash_input.length(),temp);
            if(first){
                memcpy(res,temp,SHA_256_SIZE);
                first = false;
            }else{
                Hashxor(res,temp,SHA_256_SIZE,res);
            }
            message = NULL;
            free(temp);
        }
    }
}


she::EncryptedArray homomorAdd(unsigned char* e1,int e1_len,unsigned char* e2,int e2_len){
    //she::EncryptedArray res;

    std::string e1_string = unsignedcharToString(e1,e1_len);
    std::stringstream ss(e1_string);
    boost::archive::text_iarchive ia(ss);
    she::CompressedCiphertext e_1;
    ia>>e_1;
    ss.clear();

    std::string e2_string = unsignedcharToString(e2,e2_len);
    ss<<e2_string;
    boost::archive::text_iarchive ia2(ss);
    she::CompressedCiphertext e_2;
    ia2>>e_2;
    ss.clear();

    auto res = e_1.expand() ^ e_2.expand();
    return res;
}
//unsigned char -> she::CompressedCiphertext
she::CompressedCiphertext e_transfer(unsigned char* e){
    she::CompressedCiphertext r;
    std::string e_string = (char*)e;
    std::stringstream ss(e_string);
    boost::archive::text_iarchive ia(ss);
    test();
    ia>>r;
    ss.clear();
    return r;
}

//she::EncryptedArray -> unsigned char, without release the memory
unsigned char* e_transfer(she::EncryptedArray e,int& len){
    std::stringstream ss;
    boost::archive::text_oarchive oa(ss);
    oa<<e;
    unsigned char* res = (unsigned char*)malloc(ss.str().length());
    len = ss.str().length();
    ss.clear();
    return res;
}


bool isZero(unsigned char* input,int len){
    for(int i=0;i<len;i++){
        if(input[i] != '0'){
            return false;
        }
    }
    return true;
}


void test(){
    std::cout<<"test"<<std::endl;
}

void printBitmap(std::vector<bool> bitmap){
    for(int i=0;i<bitmap.size();i++){
        std::cout<<bitmap[i]<<" ";
    }
    std::cout<<std::endl;
}


std::string unsignedcharToString(unsigned char* uc,int len){
    std::string res = "";
    for(int i = 0;i<len;i++){
        res+=uc[i];
    }
    return res;
}

std::string charToString(char* c,int len){
    std::string res = "";
    for(int i = 0;i<len;i++){
        res+=c[i];
    }
    return res;
}

unsigned char* bitmap_tranfer(std::vector<bool> bs){
    unsigned char* res = (unsigned char*)malloc(bs.size());
    for(int i=0;i<bs.size();i++){
        if(bs[i] == 1){
            res[i] = '1';
        }else if(bs[i] == 0){
            res[i] = '0';
        }
    }
    return res;
}

std::vector<bool> bitmap_tranfer(unsigned char* bs,int bs_len){
    std::vector<bool> res;
    for(int i=0;i<bs_len;i++){
        if(bs[i] == '0'){
            res.push_back(0);
        }else if(bs[i] == '1'){
            res.push_back(1);
        }
    }
    return res;
}


uint64_t timeSinceEpochMillisec() {//截取以纪元时间为单位获取当前时间戳，以毫秒为单位
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
