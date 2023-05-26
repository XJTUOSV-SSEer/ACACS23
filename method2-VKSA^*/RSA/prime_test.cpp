#include<gmp.h>
#include<iostream>
#include<algorithm>
#include<openssl/rand.h>
#include"openssl/sha.h"
#define SHA_256_SIZE 32
#define N 10
using namespace std;

string mstr = "9999999999999999999999999999999999999999";

int hash_sha256(unsigned char* message,size_t len,unsigned char* res){
    SHA256_CTX* ctx = new SHA256_CTX();
    SHA256_Init(ctx);
    SHA256_Update(ctx,message,len);
    SHA256_Final(res,ctx);
    return 32;
}

void print(unsigned char* str,int len){
    for(int i=0;i<len;i++){
        cout<<(int)str[i];
    }
    printf("\n");
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
			c1.at(i)+=N;
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

//转为十进制
string hashToDecimal(unsigned char* hash,int len){
    string decimal = "";
    for(int i=0;i<len;i++){
        decimal += to_string((int)hash[i]);
    }
    // mpz_t m;
    // mpz_t r;
    // mpz_init(m);
    // mpz_init(r);
    // mpz_set_str(r,decimal.c_str(),10);
    // mpz_set_str(m,mstr.c_str(),10);

    // mpz_mod(r,r,m);

    // char * charres= mpz_get_str(NULL,10,r);
    // string res = charres;

    // mpz_clear(m);
    // mpz_clear(r);
    string res = mod(decimal,mstr);
    return res;
}

string findPrime(string decimalHash){
    mpz_t n;
    mpz_init(n);

    mpz_set_str(n,decimalHash.c_str(),10);
    mpz_nextprime(n,n);

    char * charres = mpz_get_str(NULL,10,n); 
    string res = charres;

    mpz_clear(n);
    return charres;
}

int main(){
    unsigned char* st_w = (unsigned char*)malloc(SHA_256_SIZE);
    RAND_bytes(st_w,SHA_256_SIZE);
    cout<<"st_w: ";
    print(st_w,SHA_256_SIZE);

    unsigned char* h_w = (unsigned char*)malloc(SHA_256_SIZE);
    hash_sha256(st_w,SHA_256_SIZE,h_w);

    // mpz_t n;
    // mpz_init(n);
    //string acP="253699952048629878783745260665553993359";
    string acP=hashToDecimal(h_w,SHA_256_SIZE);
    cout<<"acP:"<<acP<<endl;
    cout<<"acP_length:"<<acP.length()<<endl;

    string res = findPrime(acP);
    cout<<"Gen:"<<res<<endl;

    // mpz_set_str(n,acP.c_str(),10);
    // mpz_nextprime(n,n);
    // cout<<"Gen:";
    // mpz_out_str(stdout,10,n);
    // printf("\n");
    //mpz_clear(n);


    free(st_w);
    free(h_w);
    return 0;
}