#include "EnclaveUtils.h"
#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "../common/data_type.h"
#include <algorithm>
#include <string.h>

using std::string;

void printf( const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void print_bytes(uint8_t *ptr, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    printf("%x", *(ptr + i));
  }

  printf("\n");
}


int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        if (*(value1+i) != *(value2+i)) {
        return -1;
        }
    }

    return 0;
}

void  clear(uint8_t *dest, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        *(dest + i) = 0;
    }
}

//将文档 content分词，分词符号为","
std::vector<std::string>  wordTokenize(char *content,int content_length){
    char delim[] = ",";//" ,.-";
    std::vector<std::string> result;

    char *content_cpy = (char*)malloc(content_length);
    memcpy(content_cpy,content,content_length);

    char *token = strtok(content_cpy,delim);
    while (token != NULL)
    {
        result.push_back(token); 
        token =  strtok(NULL,delim);
    }

    free(token);
    free(content_cpy);
    
    return result;
}

//PRF
void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, entryKey *k ){

    //k->content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	//k->content = (char *) malloc(k->content_length);
	enc_aes_gcm(key,plaintext,plaintext_len,k->content,k->content_length);

}

void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, entryValue *v){

    //v->message_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	//v->message = (char *) malloc(v->message_length);
	enc_aes_gcm(key,plaintext,plaintext_len,v->message,v->message_length);
}


void prf_Dec_Improve(const void *key,const void *ciphertext,size_t ciphertext_len, entryValue *value ){


    //value->message_length = ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	//value->message = (char *) malloc(value->message_length);
    dec_aes_gcm(key,ciphertext,ciphertext_len,value->message,value->message_length);
}

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext, size_t ciphertext_len)
{
  uint8_t p_dst[ciphertext_len] = {0};

  //p_dst = mac + iv + cipher
	sgx_rijndael128GCM_encrypt(
    (sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) plaintext, plaintext_len,
		p_dst + AESGCM_MAC_SIZE + AESGCM_IV_SIZE, //where  the cipher should be stored
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) p_dst);	//the tag should be the first 16 bytes and auto dumped out

  memcpy(p_dst + AESGCM_MAC_SIZE, gcm_iv, AESGCM_IV_SIZE);

  //copy tag+iv+cipher to ciphertext
  memcpy(ciphertext,p_dst,ciphertext_len);

}

void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len){
    
    uint8_t p_dst[plaintext_len] = {0};

	sgx_status_t ret = sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) (ciphertext + AESGCM_MAC_SIZE + AESGCM_IV_SIZE), plaintext_len,
		p_dst,
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) ciphertext); //get the first 16 bit tag to verify

	memcpy(plaintext, p_dst, plaintext_len);

}

int hash_SHA256(const void *msg,int msg_len,void* value){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_sha256_msg((uint8_t*)msg,msg_len,(sgx_sha256_hash_t*)value);//32位，256bit
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        printf("[*] hash error line 87: %d\n", ret);
        return 0;
    }  
}

int hash_SHA256(const void *key,int key_len,const void* p,int p_len,void* value){
    unsigned char* msg = (unsigned char*)malloc(key_len+p_len);
    int msg_len = key_len+p_len;
    memcpy(msg,key,key_len);
    memcpy(msg+key_len,p,p_len);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_sha256_msg((uint8_t*)msg,msg_len,(sgx_sha256_hash_t*)value);//32位，256bit
    free(msg);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        printf("[*] hash error line 87: %d\n", ret);
        return 0;
    }  
}

//generating 128bit output digest
int hash_SHA128(const void *key, const void *msg, int msg_len, void *value){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_rijndael128_cmac_msg(
            (sgx_cmac_128bit_key_t *)key,
            (const uint8_t*)msg,
            msg_len,
            (sgx_cmac_128bit_tag_t*)value); //16位，128bit
     
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        printf("[*] hash error line 87: %d\n", ret);
        return 0;
    }  
}

//make sure the key is 16 bytes and appended to the digest
//这是在hash结束后的value后面加上16位的key
int hash_SHA128_key(const void *key, int key_len, const void *msg, int msg_len, void *value){
    
    int result;
    result = hash_SHA128(key,msg,msg_len,value);
    if (result==1) {
        //这是在hash结束后的value后面加上16位的key
        memcpy(value+ENTRY_HASH_KEY_LEN_128,key,key_len); 
        return 1;
    } else{
        printf("[*] hash error line 163: %d\n", result);
        return 0;
    }
}

void Hashxor(unsigned char* hash1,unsigned char* hash2,int len,unsigned char* res){
    for(int i=0;i<len;i++){
        res[i] = hash1[i] ^ hash2[i];
    }
}

void Hashand(unsigned char* hash1,unsigned char* hash2,int len,unsigned char* res){
    for(int i=0;i<len;i++){
        res[i] = hash1[i] & hash2[i];
    }
}


void getMultiHash(std::vector<bool> bitmap,unsigned char* res,unsigned char* K,int K_len){
    std::string input = unsignedcharToString(K,K_len);
    bool first = true;
    for(int i=0;i<bitmap.size();i++){
        if(bitmap[i] == 1){
            unsigned char* temp = (unsigned char*)malloc(SHA_256_SIZE);
            std::string hash_input = input + std::to_string(i);
            unsigned char* message = (unsigned char*)hash_input.c_str();
            hash_SHA256(message,hash_input.length(),temp);
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

std::vector<bool> bitmap_transfer(unsigned char* bs,int bs_len){
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

std::string charToString(char* c,int len){
    std::string res = "";
    for(int i = 0;i<len;i++){
        res+=c[i];
    }
    return res;
}

std::string unsignedcharToString(unsigned char* uc,int len){
    std::string res = "";
    for(int i = 0;i<len;i++){
        res+=uc[i];
    }
    return res;
}

bool unsignedcharCmp(unsigned char* uc1,unsigned char* uc2,int len){
    for(int i=0;i<len;i++){
        if(uc1[i] != uc2[i]){
            return false;
        }
    }
    return true;
}

std::string hashToDecimal(unsigned char* hash,int len){
    std::string decimal = "";
    for(int i=0;i<len;i++){
        decimal += std::to_string((int)hash[i]);
    }
    std::string res = mod(decimal,mstr);
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

string ex_gcd(string a,string b, string &x,string &y){
	// cout << "x:" << x << " y:" << y << " a:" << a << " b:" << b << endl;
	if(b == "0"){
		x = "1";
		y = "0";
		return a;
	}
	string r = ex_gcd(b,mod(a,b),y,x);
	y= Minus(y,multiply(divide(a,b),x)); 

	//cout << "x:" << x  << " r:" << r << " y:" << y << " a:" << a << " b:" << b << endl;
	return r;
}

string Minus(string a,string b){
	string res = "";
	if(a[0] == '-' && b[0] != '-'){
		res = '-';
		res += add(a.substr(1,a.length()-1),b.substr(0,b.length()));
	}else if(a[0] != '-' && b[0] == '-'){
		res = add(a.substr(0,a.length()),b.substr(1,b.length()-1));
	}else if(a[0] == '-' && b[0] == '-'){
		res = minuss(b.substr(1,b.length()-1),a.substr(1,a.length()-1));
	}else{
		res = minuss(a.substr(0,a.length()),b.substr(0,b.length())); 
	}
	return res;
}

string add(string str1,string str2){
	string res = "";
	int maxn = str1.length() > str2.length()? str1.length()+1 : str2.length()+1;

	int a[maxn];
	int b[maxn];
	memset(a,0,sizeof(a));
	memset(b,0,sizeof(b));
	for(int i = str1.length() - 1,j = 0; i>=0;i--){
		a[j++] = str1[i] - '0';
	}
	for(int i = str2.length() - 1,j = 0; i>=0;i--){
		b[j++] = str2[i] - '0';
	}
	//相加和进位
    for(int i = 0; i < maxn; i++)
    {
        b[i] += a[i];
        //进位操作
        if(b[i] >= 10)
        {
            b[i + 1] += b[i] / 10;
            b[i] %= 10;
        }
    }
	int i;
	for(i = maxn - 1; i >= 0 && b[i] == 0; i--);
	if(i >= 0){
		for(;i>=0;i--){
			res = res + std::to_string(b[i]);
		}
	}

	return res;
}