#include"Data_User.h"
#include<iostream>

Data_User::Data_User(std::string id_u){
    this->id_u = id_u;
}

Data_User::~Data_User(){
    free(st.K_u);
    free(st.K_w);
    free(st.st_u);
    free(st.st_w);
}

void Data_User::Search_request(std::string w,Data_Owner* data_owner){
    //K_w
    unsigned char* ucw = (unsigned char*)w.c_str();
    unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
    int K_w_length = data_owner->genK_w(ucw,strlen((const char*)ucw),K_w);

    //K_u
    unsigned char* ucu = (unsigned char*)id_u.c_str();
    unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
    int K_u_length = data_owner->genK_u(ucu,strlen((const char*)ucu),K_u);

    //w
    unsigned char* st_w = data_owner->getST1(w).st_w;
    int c_w = data_owner->getST1(w).c_w;
    unsigned char* h_w = data_owner->getST1(w).h_w;

    //u
    unsigned char* st_u = data_owner->getST2(id_u).st_u;
    int c_u = data_owner->getST2(id_u).c_u;
    unsigned char* h_u = data_owner->getST2(id_u).h_u;

    st.c_u = c_u;
    st.c_w = c_w;

    st.K_u_length = K_u_length;
    st.K_u = (unsigned char*)malloc(K_u_length);
    memcpy(st.K_u,K_u,K_u_length);
    free(K_u);

    st.K_w_length = K_w_length;
    st.K_w = (unsigned char*)malloc(K_w_length);
    memcpy(st.K_w,K_w,K_w_length);
    free(K_w);

    st.st_u_length = data_owner->getST2(id_u).st_u_len;
    st.st_u = (unsigned char*)malloc(st.st_u_length);
    memcpy(st.st_u,st_u,st.st_u_length);
    free(st_u);

    st.st_w_length = data_owner->getST1(w).st_w_len;
    st.st_w = (unsigned char*)malloc(st.st_w_length);
    memcpy(st.st_w,st_w,st.st_w_length);
    free(st_w);

    st.w_len = w.length();
    st.w = (char*)malloc(st.w_len);
    memcpy(st.w,w.c_str(),st.w_len);

    st.id_u_len = id_u.length();
    st.id_u = (char*)malloc(st.id_u_len);
    memcpy(st.id_u,id_u.c_str(),st.id_u_len);
}


search_token Data_User::send_search_token(){
    return st;
}


void Data_User::getSearchRes(std::vector<bool> res){
    std::cout<<"------Search result------"<<std::endl;
    for(int i=0;i<res.size();i++){
        if(res[i] == 1){
            std::cout<<"index: "<<i<<"\te.g\t"<<"File id: "<<100-i<<std::endl;
        }
    }
}
