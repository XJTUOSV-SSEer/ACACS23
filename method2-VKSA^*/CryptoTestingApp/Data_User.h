#ifndef DATA_USER_H
#define DATA_USER_H

#include<string>
#include"Data_Owner.h"
#include"../common/data_type.h"


class Data_User{
    private:
        search_token st; //search token (DU发送给server)

    public:
        Data_User(std::string id_u);
        std::string id_u; //ID_u
        ~Data_User();
        void Search_request(std::string w,Data_Owner* data_owner); //DU向DO索取search token
        search_token send_search_token(); //DU像server发送search token
        void getSearchRes(std::vector<bool> res,std::string w,std::string pi_w,std::string pi_u,std::string acc);

};


#endif