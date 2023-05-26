#ifndef DATA_OWNER_H
#define DATA_OWNER_H
#include "../common/data_type.h"
#include "Utils.h"
#include <sstream> 
#include <unordered_map>
#include <vector>
#include <chrono>
#include "Server.h"

class Data_Owner{
    public:
        Data_Owner();
        ~Data_Owner();
        void build();
        void build_w();
        void build_id_u();
        void build(Server* server);
        void build_w(Server* server);
        void build_id_u(Server* server);
        std::pair<std::string,I1_value> update_w(std::string w,std::vector<bool> bitmap_w,T_w_value& T_value);
        std::pair<std::string,I2_value> update_u(std::string u,std::vector<bool> bitmap_u,T_u_value& T_value);
        std::unordered_map<std::string,std::vector<bool>> loadData(std::string folder_name,int number);
        std::vector<bool> dec_e_w(unsigned char* e_w); 
        std::vector<bool> dec_e_u(unsigned char* e_u); 
        std::vector<bool> dec_e(she::EncryptedArray e,int Type);

        std::unordered_map<std::string,T_w_value> sendT_w();
        std::unordered_map<std::string,T_u_value> sendT_u();
        std::unordered_map<std::string,I1_value> sendI1();
        std::unordered_map<std::string,I2_value> sendI2();
        int genK_w(unsigned char* ucw,int ucw_len,unsigned char* K_w);
        int genK_u(unsigned char* ucu,int ucu_len,unsigned char* K_u);
        ST1_value getST1(std::string w);
        ST2_value getST2(std::string id_u);
        //void test();

        void display_bs_w(std::string w);
        
    private:
        unsigned char K_s[ENC_KEY_SIZE];
        ParameterSet secure_p_w;
        ParameterSet secure_p_u;
        PrivateKey* sk_u;
        PrivateKey* sk_w;
        int n;
        std::unordered_map<std::string,ST1_value> ST1;
        std::unordered_map<std::string,I1_value> I1;
        std::unordered_map<std::string,T_w_value> T_w;
        std::unordered_map<std::string,ST2_value> ST2;
        std::unordered_map<std::string,I2_value> I2;
        std::unordered_map<std::string,T_u_value> T_u;
        std::unordered_map<std::string,std::vector<int>> index_w;//record ind = 1 for each w , index instead of fileid, start with 0
        std::unordered_map<std::string,std::vector<int>> index_u;//record ind = 1 for each u

        uint64_t intervel;
};


#endif