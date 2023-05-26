#ifndef DATA_OWNER_H
#define DATA_OWNER_H
#include "../common/data_type.h"
#include "Utils.h"
#include <sstream> 
#include <unordered_map>
#include <vector>
#include "Server.h"
// uint64_t timeSinceEpochMillisec() {//截取以纪元时间为单位获取当前时间戳，以毫秒为单位

//   using namespace std::chrono;
//   return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
// }

class Data_Owner{
    public:
        Data_Owner();
        ~Data_Owner();
        void build();
        void build_w();
        void build_id_u();
        void build(Server* server); //Build过程
        void build_w(Server* server); //构建w过程
        void build_id_u(Server* server); //构建ID_u过程
        std::pair<std::string,I1_value> update_w(std::string w,std::vector<bool> bitmap_w,T_w_value& T_value);
        std::pair<std::string,I2_value> update_u(std::string u,std::vector<bool> bitmap_u,T_u_value& T_value);
        std::pair<std::string,I1_value> update_w(std::string w,std::vector<bool> bitmap_w,T_w_value& T_value,Server* myServer); //关键字索引更新
        std::pair<std::string,I2_value> update_u(std::string u,std::vector<bool> bitmap_u,T_u_value& T_value,Server* myServer); //授权索引更新
        std::unordered_map<std::string,std::vector<bool>> loadData(std::string folder_name,int number); //加载数据
        std::vector<bool> dec_e_w(unsigned char* e_w); 
        std::vector<bool> dec_e_u(unsigned char* e_u); 
        std::vector<bool> dec_e(she::EncryptedArray e,int Type);

        std::unordered_map<std::string,T_w_value> sendT_w();
        std::unordered_map<std::string,T_u_value> sendT_u();
        std::unordered_map<std::string,I1_value> sendI1();
        std::unordered_map<std::string,I2_value> sendI2();
        int genK_w(unsigned char* ucw,int ucw_len,unsigned char* K_w); //生成k_w
        int genK_u(unsigned char* ucu,int ucu_len,unsigned char* K_u); //生成k_u
        ST1_value getST1(std::string w); //取回 st_w,c_w,h_w
        ST2_value getST2(std::string id_u); //取回 st_u,c_u,h_u
        std::string sendAcc(); //返回acc
        std::string sendProduct();
        
        //void test();

        void display_bs_w(std::string w);
        
    private:
        unsigned char K_s[ENC_KEY_SIZE]; //安全密钥k_s
        ParameterSet secure_p_w;
        ParameterSet secure_p_u;
        PrivateKey* sk_u; //w的对称同态加密密钥sk_u
        PrivateKey* sk_w; //w的对称同态加密密钥sk_w
        int n;
        std::string product; //累成结果
        std::string acc; //RSA accumulatore value
        std::unordered_map<std::string,ST1_value> ST1; //关键字w对应状态表
        std::unordered_map<std::string,I1_value> I1; //关键字索引
        std::unordered_map<std::string,T_w_value> T_w;
        std::unordered_map<std::string,ST2_value> ST2; //user ID_u 对应状态表
        std::unordered_map<std::string,I2_value> I2; //授权索引
        std::unordered_map<std::string,T_u_value> T_u;
        std::unordered_map<std::string,std::vector<int>> index_w;//record ind = 1 for each w , index instead of fileid, start with 0
        std::unordered_map<std::string,std::vector<int>> index_u;//record ind = 1 for each u
        uint64_t intervel;

};


#endif