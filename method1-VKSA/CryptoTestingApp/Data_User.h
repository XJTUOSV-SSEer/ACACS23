#ifndef DATA_USER_H
#define DATA_USER_H

#include<string>
#include"Data_Owner.h"
#include"../common/data_type.h"


class Data_User{
    private:
        search_token st;

    public:
        Data_User(std::string id_u);
        std::string id_u;
        ~Data_User();
        void Search_request(std::string w,Data_Owner* data_owner);
        search_token send_search_token();
        void getSearchRes(std::vector<bool> res);

};


#endif