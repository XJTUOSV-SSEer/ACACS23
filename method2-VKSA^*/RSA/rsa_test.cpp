#include<iostream>
#include<string>
#include<algorithm>
#include<string.h>
using namespace std;
#define n 10
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
			c3.at(i+j+1)+=kai/n;
			c3.at(i+j)+=kai%n;
			for(k=i+j;k<c3.length()-1;k++)
			{
				if(c3.at(k)>=n) 
				{
					c3.at(k+1)+=c3.at(k)/n;
					c3.at(k)=c3.at(k)%n;
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
			c1.at(i)+=n;
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
			res = res + to_string(b[i]);
		}
	}

	return res;
}


int cmp(string a,int a_start,int a_n,string b,int b_start,int b_n){
	if(a_n > b_n){
		return 1;
	}else if(a_n < b_n){
		return -1;
	}else if(a_n == b_n){
		string temp_a = a.substr(a_start,a_n);
		string temp_b = b.substr(b_start,b_n);
		return temp_a.compare(0,a_n,temp_b,0,b_n);
	}
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

string minuStrings(string num1, string num2){
	//num1位数大于num2
	if (num1.size() < num2.size())
	{
		num1.swap(num2);
	}

	string ret(num1.size(), '0');
	char step = 0;
	for (int iL = num1.size() - 1, iR = num2.size() - 1; iL >= 0; iL--, iR--)
	{
		char ch = num1[iL] - '0' - step;
		step = 0;

		if (iR >= 0)
		{
			if ((num1[iL] - '0') < (num2[iR] - '0'))
			{
				step = 1;
				ch += 10;
			}
			ch -= num2[iR] - '0';
		}
		if (iR < 0 && ch < 0)
		{
			step = 1;
			ch += 10;
		}

		ret[iL] += ch;
	}
	if (step == 1)
	{
		ret[0] -= 1;
	}

	while (ret[0] == '0')
	{
		ret.erase(ret.begin());
	}

	return ret;
}


int main()
{
    string acP="253699952048629878783745260665553993359";
    string acQ="284802804588708767570121178795305085943";
    string acP_1="253699952048629878783745260665553993358";
    string acQ_1="284802804588708767570121178795305085942";
    string acN = "72254457867470719938938495559676057516509089362369981914474612970086346252537";
    string acG = "4";

    string x_0 = "222681710225944171422886330904366434499";
    string x_1 = "185746510016684497032519028847048130763";
	string x_2 = "253699952048629878783745260665553993359";



	// string acP="23";
    // string acQ="19";
    // string acP_1="22";
    // string acQ_1="18";
    // string acN = "437";
    // string acG = "4";

    // string x_0 = "7";
    // string x_1 = "11";
    string product = multiply(x_0,x_1);

	// for(int i=0; i < 10000; i++){
	// 	product = multiply(x_0, product);
	// }
	cout << "output:"<< product <<endl;

    string temp1 = multiply(acP_1,acQ_1);
    string temp2 = mod(product,temp1);
    string Ac = quickpower(acG,temp2,acN);
    cout << "Acc:" << Ac << endl;

	cout<<"****************method1************" << endl; 
    string xx = x_0;
    string temp3 = divide(product,xx);
    cout << "temp3:" << temp3 << endl;
    string vo = quickpower(acG,temp3,acN);
    cout << "vo:" << vo << endl;
    string verify_vo = quickpower(vo,xx,acN);
    cout << "verify_vo:" << verify_vo << endl;
    if(verify_vo==Ac){
        cout<<"True"<<endl;
    }


	cout<<"****************method2************" << endl;

	// 计算乘法逆元
	string x;
	string y;
	string temp = ex_gcd(xx,temp1,x,y);
	cout<<temp1<<endl;
	string inv;
	if(temp == "1"){
		inv = mod(add(mod(x,temp1),temp1),temp1);
	}else{
		inv = "-1";
	}
	cout<<"inv:"<<inv<<endl;
	string temp4 =  mod(inv,temp1);
	vo = quickpower(Ac,temp4,acN);
    cout << "vo:" << vo << endl;


	verify_vo = quickpower(vo,xx,acN);
    cout << "verify_vo:" << verify_vo << endl;
	if(verify_vo==Ac){
        cout<<"True"<<endl;
    }


	// string num = Minus("-4","95");
	// cout<<"num:" << num << endl;


	// cout<<"*************test_gcd**************" << endl;
	// string a = "11";
	// string b = "8";
	// string x;
	// string y;
	// if(ex_gcd(a,b,x,y) == "1"){
	// 	cout<<mod(add(mod(x,b),b),b)<<endl;
	// }else{
	// 	cout<<-1<<endl;
	// }
	// return 0;
}
