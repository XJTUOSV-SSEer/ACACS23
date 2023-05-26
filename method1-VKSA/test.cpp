#include<iostream>
#include<she.hpp>
#include <boost/archive/text_oarchive.hpp> 
#include <boost/archive/text_iarchive.hpp> 
#include <vector>
#include<sstream>

using she::ParameterSet;
using she::PrivateKey;
using namespace std;

int main(){
    she::ParameterSet secure_p_w = ParameterSet::generate_parameter_set(30, 1, 42);
    const she::PrivateKey sk(secure_p_w);
    const she::PrivateKey sk2(secure_p_w);
    vector<bool> v1 = {1, 1, 1, 1, 1, 1, 1, 1};
    const she::CompressedCiphertext compressedC1 = sk.encrypt(v1);
    //vector<bool> v2 = {0, 1, 0, 1, 0, 1, 0, 1};
    vector<bool> v2(10000,1);
    const she::CompressedCiphertext compressedC2 = sk.encrypt(v2);


    stringstream ss1;
    boost::archive::text_oarchive oa(ss1);
    oa<<compressedC2;
    cout << "compressed:" << ss1.str().length() << endl;

    auto res = compressedC2.expand();
    ss1.clear();
    boost::archive::text_oarchive oa1(ss1);
    oa1<<compressedC2;
    cout << "Uncompressed:" << ss1.str().length() << endl;



    // auto res = compressedC1.expand() ^ compressedC2.expand();

    // stringstream ss1;
    // boost::archive::text_oarchive oa(ss1);
    // oa<<res;

    // unsigned char* e = (unsigned char*)malloc(ss1.str().length());
    // memcpy(e,(unsigned char*)ss1.str().c_str(),ss1.str().length());

    // string s = (char*)e;

    // stringstream ss2(s);
    // boost::archive::text_iarchive ia(ss2);
    // she::EncryptedArray res2;
    // ia>>res2;


    // vector<bool> r = sk.decrypt(res2);

    // for(int i=0;i<r.size();i++){
    //     cout<<r[i]<<endl;
    // }
}