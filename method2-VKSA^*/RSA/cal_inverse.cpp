#include<bits/stdc++.h>
using namespace std;
// typedef long long ll;
// void exgcd(ll a,ll b,ll& d,ll& x,ll& y){
//     if(!b) { d = a; x = 1; y = 0; }
//     else{ exgcd(b, a%b, d, y, x); y -= x*(a/b); }
// }
// ll inv(ll a, ll p){
//     ll d,x,y;
//     exgcd(a,p,d,x,y);
//     return d == 1 ? (x+p)%p : -1;
// }
// int main()
// {
//     ll a,p;
//     while(1){
//         scanf("%lld %lld",&a,&p);
//         printf("%lld\n",inv(a,p));
//     }
// }
int ex_gcd(int a, int b, int &x, int &y) {  // 函数返回gcd(a, b)
    // cout << "x:" << x << " y:" << y << " a:" << a << " b:" << b << endl;
    if (b == 0) {
        x = 1, y = 0;
        return a;
    }
    int r = ex_gcd(b, a % b, y, x);
    int temp;
    temp = y - (a / b) * x;
    // y -= (a / b) * x;
    
    cout << "x:" << x  << " r:" << r << " y:" << y << " a:" << a << " b:" << b << endl;
    y = temp;
    return r;
}
 
int main() {
    int a, b, x=0, y=0;
    cin >> a >> b;  // 求a关于模b的逆元
    cout << (ex_gcd(a, b, x, y) == 1 ? (x % b + b) % b : -1) << endl;  // -1表示逆元不存在
 
    return 0;
}
