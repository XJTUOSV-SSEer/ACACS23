#ifndef SERVER_H
#define SERVER_H

#include "../common/data_type.h"
#include "Utils.h"
#include <sstream>
#include "sgx_urts.h"

class Server{
    public:
        Server(); //构造函数 MIMC初始化
        ~Server();//析构函数 MIMC初始化
        void ReceiveEncDoc(entry *encrypted_doc);
        void ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 rand_t *t2_u_arr,rand_t *t2_v_arr,
                                 int pair_count);
        std::string Retrieve_Encrypted_Doc(std::string del_id_str);
        std::string Retrieve_M_c(std::string u_prime_str);
        
        void Del_Encrypted_Doc(std::string del_id_str);
        void Del_M_c_value(std::string del_u_prime);

        void Display_Repo();
        void Display_M_I();
        void Display_M_c();
        void Display_EDB1();

        std::vector<std::string> retrieve_query_results(
								rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,
								int pair_count);

        void getEDB1(std::unordered_map<std::string,I1_value> I1);
        void getEDB2(std::unordered_map<std::string,I2_value> I2);
        void getI1Value(std::pair<std::string,I1_value> value); //将密文对插入关键字索引
        void getI2Value(std::pair<std::string,I2_value> value); //将密文对插入授权索引
        serverSearchRes getSearch_token(search_token st); //从DU获取search token进行查询

        void getProduct(std::string product);
        void updateProduct(std::string old_h,std::string new_h);

        std::string sendProduct();

    private:
        std::unordered_map<std::string,std::string> M_I;
        std::unordered_map<std::string,std::string> M_c;
        std::unordered_map<std::string,std::string> R_Doc;

        std::unordered_map<std::string,I1_value> EDB1; //关键字索引EDB1
        std::unordered_map<std::string,I2_value> EDB2; //授权索引EDB2
        std::string product; //累成值 (RSA accumulator)
        
};
 
#endif
