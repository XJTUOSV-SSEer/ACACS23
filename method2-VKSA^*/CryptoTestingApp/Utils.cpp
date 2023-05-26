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

string hashToDecimal(unsigned char* hash,int len){
    string decimal = "";
    for(int i=0;i<len;i++){
        decimal += std::to_string((int)hash[i]);
    }
    string res = mod(decimal,mstr);
    return res;
}

int judge(string a,string b)//判断两个正数的大小
{
	if(a.length()>b.length()) return 1;
	if(a.length()<b.length()) return -1;
	long int i;
	for(i=0;i<a.length();i++)
	{
		if(a.at(i)>b.at(i)) return 1;
		if(a.at(i)<b.at(i)) return -1;
	}
	return 0;
}

string dezero(string a)//用来去掉正数前面的0，也就是说可以输入000001类似这样的数字
{
	long int i;
	for(i=0;i<a.length();i++)
	{
		if(a.at(i)>48) break;
	}
	if(i==a.length()) return "0";
	a.erase(0,i);
	return a;
}

string minuss(string a,string b)//自然数减法
{
	a=dezero(a);
	b=dezero(b);
	long int i,j=0;
	string c="0";
	string c1,c2;
	string d="-";
	if(judge(a,b)==0) return c;
	if(judge(a,b)==1)
	{
		c1=a;
		c2=b;
	}
	if(judge(a,b)==-1)
	{
		c1=b;
		c2=a;
		j=-1;
	}
	reverse(c1.begin(),c1.end());
	reverse(c2.begin(),c2.end());
	for(i=0;i<c2.length();i++)
	{
		if(c2.at(i)>=48&&c2.at(i)<=57) c2.at(i)-=48;
		if(c2.at(i)>=97&&c2.at(i)<=122) c2.at(i)-=87;
	}
	for(i=0;i<c1.length();i++)
	{
		if(c1.at(i)>=48&&c1.at(i)<=57) c1.at(i)-=48;
		if(c1.at(i)>=97&&c1.at(i)<=122) c1.at(i)-=87;
	}
	for(i=0;i<c2.length();i++)
	{
		c1.at(i)=c1.at(i)-c2.at(i);
	}
	for(i=0;i<c1.length()-1;i++)
	{
		if(c1.at(i)<0)
		{
			c1.at(i)+=NN;
			c1.at(i+1)--;
		}
	}
	for(i=c1.length()-1;i>=0;i--)
	{
		if(c1.at(i)>0) break;
	}
	c1.erase(i+1,c1.length());
	for(i=0;i<c1.length();i++)
	{
		if(c1.at(i)>=10) c1.at(i)+=87;
		if(c1.at(i)<10) c1.at(i)+=48;
	}
	reverse(c1.begin(),c1.end());
	if(j==-1) c1.insert(0,d);
	return c1;
}

string mod(string a,string b)
{
	long int i,j=0;
	string c1,c2,c3,d;
	if(a.at(0)=='-') j=1;
	if(judge(a,b)==0) return "0";
	if(judge(a,b)==-1)
	{
		return dezero(a);
	}
	c1=dezero(a);
	c2=dezero(b);
	d="";
	for(i=0;i<c1.length();i++)
	{
		d=d+c1.at(i);
		while(judge(d,b)>=0)
		{
			d=minuss(d,b);
			d=dezero(d);
		}
	}
	if(j==1) d=minuss(b,d);
	return dezero(d);
}

string multiply(string a,string b)//整数
{
	long int i,j,k,yao=0,kai;
	string c1,c2;
	string c3=a+b;
	if(a.at(0)=='-')
	{
		a.erase(0,1);
		yao++;
	}
	if(b.at(0)=='-')
	{
		b.erase(0,1);
		yao++;
	}
	a=dezero(a);
	b=dezero(b);
	if(a.at(0)==48||b.at(0)==48) return "0";
	if(a.length()>b.length())
	{
		c1=a;
		c2=b;
	}
	else
	{
		c1=b;
		c2=a;
	}
	reverse(c1.begin(),c1.end());
	reverse(c2.begin(),c2.end());
	for(i=0;i<c2.length();i++)
	{
		if(c2.at(i)>=48&&c2.at(i)<=57) c2.at(i)-=48;
		if(c2.at(i)>=97&&c2.at(i)<=122) c2.at(i)-=87;
	}
	for(i=0;i<c1.length();i++)
	{
		if(c1.at(i)>=48&&c1.at(i)<=57) c1.at(i)-=48;
		if(c1.at(i)>=97&&c1.at(i)<=122) c1.at(i)-=87;
	}
	for(i=0;i<c3.length();i++) c3.at(i)=0;
	for(i=0;i<c2.length();i++)
	{
		for(j=0;j<c1.length();j++)
		{
			kai=c2.at(i)*c1.at(j);
			c3.at(i+j+1)+=kai/NN;
			c3.at(i+j)+=kai%NN;
			for(k=i+j;k<c3.length()-1;k++)
			{
				if(c3.at(k)>=NN) 
				{
					c3.at(k+1)+=c3.at(k)/NN;
					c3.at(k)=c3.at(k)%NN;
				}
				else
				{
					break;
				}
			}
		}
	}
	for(i=c3.length()-1;i>=0;i--)
	{
		if(c3.at(i)>0) break;
	}
	c3.erase(i+1,c3.length());
	for(i=0;i<c3.length();i++)
	{
		if(c3.at(i)>=10) c3.at(i)+=87;
		if(c3.at(i)<10) c3.at(i)+=48;
	}
	reverse(c3.begin(),c3.end());
	if(yao==1) c3="-"+c3;
	return c3;
}

string divide(string a,string b)//正整数除法
{
	if(b.length()==1&&b.at(0)==48) return "error";
	long int i,j;
	string c1,c2,d,e;
	if(judge(a,b)==0) return "1";
	if(judge(a,b)==-1)
	{
		return "0";
	}
	c1=dezero(a);
	c2=dezero(b);
	d="";
	e="";
	for(i=0;i<c1.length();i++)
	{
		j=0;
		d=d+c1.at(i);
		d=dezero(d);
		while(judge(d,b)>=0)
		{
			d=minuss(d,b);
			d=dezero(d);
			j++;
		}
		e=e+"0";
		e.at(i)=j;
	}
	for(i=0;i<e.length();i++)
	{
		if(e.at(i)>=10) e.at(i)+=87;
		if(e.at(i)<10) e.at(i)+=48;
	}
	e=dezero(e);
	return e;
}

string quickpower(string a,string b,string c)//快速指数算法a的b次方mod c
{
	//进制转换
	string e;
	long int i;
	i=0;
	while(1)
	{
		if(b.length()==1&&b.at(0)==48) break;
		e=e+"0";
		e.at(i)=mod(b,"2").at(0);
		b=divide(b,"2");
		i++;
	}
	reverse(e.begin(),e.end());
	//快速指数算法
	b=e;
	string d="1";
	for(i=0;i<b.length();i++)
	{
		if(b.at(i)==49) d=multiply(d,a);
		if(i!=b.length()-1) d=multiply(d,d);
		d=mod(d,c);
	}
	return d;
}

uint64_t timeSinceEpochMillisec() {//截取以纪元时间为单位获取当前时间戳，以毫秒为单位
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}


