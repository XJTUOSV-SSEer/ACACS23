#include<iostream>
#include<string>
#include<algorithm>
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

string Add(string a, string b)
{
	string c = "";
	int bit = -1; //判断是否进位 -1为否，其他为进位数
	int i = a.length()-1; //获得a字符串长度
	int j = b.length()-1; //获得b字符串长度
	//第一种情况 两者都处理完
	while (i != -1 && j != -1)
	{
		int t1 = a[i] - 48; 
		int t2 = b[j] - 48;
		//不存在进位
		if (bit == -1)
		{
			if (t1 + t2 >= 10)
			{
				int d = (t1 + t2) % 10;
				c.insert(0, 1, d + 48);
				bit = (t1 + t2) / 10;
			}
			else
			{
				c.insert(0, 1, t1 + t2 + 48);
			}
		}
		//存在进位
		else
		{
			if (t1 + t2 + bit >= 10)
			{
				int d = (t1 + t2 + bit) % 10;
				c.insert(0, 1, d + 48);
				bit = (t1 + t2 + bit) / 10;
			}
			else
			{
				c.insert(0, 1, t1 + t2 + bit + 48);
				bit = -1;
			}
		}
		i--;
		j--;
	}
	//第二种情况 前者处理完
	while (i == -1 && j != -1)
	{
		int t2 = b[j] - 48;
		if (bit == -1)
		{
			c.insert(0, 1, b[j]);
		}
		else
		{
			if (t2 + bit >= 10)
			{
				int d = (t2 + bit) % 10;
				c.insert(0, 1, d + 48);
				bit = (t2 + bit) / 10;
			}
			else
			{
				c.insert(0, 1, t2 + bit + 48);
				bit = - 1;
			}
		}
		j--;
	}
	//第三种情况 后者处理完
	while (i != -1 && j == -1)
	{
		int t1 = a[i] - 48;
		if (bit == -1)
		{
			c.insert(0, 1, a[i]);
		}
		else
		{
			if (t1 + bit >= 10)
			{
				int d = (t1 + bit) % 10;
				c.insert(0, 1, d + 48);
				bit = (t1 + bit) / 10;
			}
			else
			{
				c.insert(0, 1, t1 + bit + 48);
				bit = -1;
			}
		}
		i--;
	}
	//最后再判断是否存在进位
	if (bit != -1)
	{
		c.insert(0, 1, bit + 48);
	}
	bit = -1;
	return c;
}

bool isPrime(string str){
	string num = "2";
	string num_2 = multiply(num,num);
	// cout << num_2 << endl;
	while(divide(num_2,str)=="0"){
		if(mod(str,num)=="0"){
			return false;
		}else{
			num = Add(num,"1");
			num_2 =  multiply(num,num);
		}
	}
	return true;
}

string str2prime(string str){
	while(true){
		if(isPrime(str)){
			return str;
		}else{
			str = Add(str,"1");
			// cout << str << endl;
		}
	}

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
    string product = multiply(x_0,x_1);

	// for(int i=0; i < 10000; i++){
	// 	product = multiply(x_0, product);
	// }




	cout << "output:"<< product <<endl;
	/*************Accumulation***************/
    string temp1 = multiply(acP_1,acQ_1);
    string temp2 = mod(product,temp1);
    string Ac = quickpower(acG,temp2,acN);
    cout << "Acc:" << Ac << endl;


    string xx = "222681710225944171422886330904366434499";

	// string xx_prime = str2prime(xx);
	// while(quickpower(xx,"2","1" )< )

	// string a = "123";
	// string b = "1234";

	// cout << str2prime(xx) << endl;


	/*************MemWit***************/
    string temp3 = divide(product,xx);
    cout << "temp3:" << temp3 << endl;
    string vo = quickpower(acG,temp3,acN);

	
    cout << "vo:" << vo << endl;

	/*************VerifyMem***************/
    string verify_vo = quickpower(vo,xx,acN);
    cout << "verify_vo:" << verify_vo << endl;
    if(verify_vo==Ac){
        cout<<"True"<<endl;
    }








	return 0;
}
