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

//DU向DO索取search token
void Data_User::Search_request(std::string w,Data_Owner* data_owner){
    //取回k_w
    unsigned char* ucw = (unsigned char*)w.c_str();
    unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
    int K_w_length = data_owner->genK_w(ucw,strlen((const char*)ucw),K_w);

    //取回k_u
    unsigned char* ucu = (unsigned char*)id_u.c_str();
    unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
    int K_u_length = data_owner->genK_u(ucu,strlen((const char*)ucu),K_u);

    //取回 st_w,c_w,h_w
    unsigned char* st_w = data_owner->getST1(w).st_w;
    int c_w = data_owner->getST1(w).c_w;
    unsigned char* h_w = data_owner->getST1(w).h_w;

    //取回st_u,c_u,h_u
    unsigned char* st_u = data_owner->getST2(id_u).st_u;
    int c_u = data_owner->getST2(id_u).c_u;
    unsigned char* h_u = data_owner->getST2(id_u).h_u;

    st.c_w = c_w; //赋值c_w

    st.K_u_length = K_u_length; //赋值K_u长度
    st.K_u = (unsigned char*)malloc(K_u_length);
    memcpy(st.K_u,K_u,K_u_length); //赋值K_u
    free(K_u);

    st.K_w_length = K_w_length; //赋值K_w长度
    st.K_w = (unsigned char*)malloc(K_w_length); //赋值K_w
    memcpy(st.K_w,K_w,K_w_length);
    free(K_w);

    st.st_u_length = data_owner->getST2(id_u).st_u_len; //取回st_u长度
    st.st_u = (unsigned char*)malloc(st.st_u_length);
    memcpy(st.st_u,st_u,st.st_u_length); //赋值st_u
    free(st_u);

    st.st_w_length = data_owner->getST1(w).st_w_len; //取回st_w长度
    st.st_w = (unsigned char*)malloc(st.st_w_length); 
    memcpy(st.st_w,st_w,st.st_w_length); //赋值st_w
    free(st_w);

    st.w_len = w.length(); //赋值搜索关键字的长度
    st.w = (char*)malloc(st.w_len); 
    memcpy(st.w,w.c_str(),st.w_len); //赋值搜索关键字

    st.id_u_len = id_u.length(); //赋值ID_u长度
    st.id_u = (char*)malloc(st.id_u_len); 
    memcpy(st.id_u,id_u.c_str(),st.id_u_len); //赋值ID_u

    st.h_w = hashToDecimal(data_owner->getST1(w).h_w,data_owner->getST1(w).h_w_len); //赋值w对应的多集合哈希值
    st.h_u = hashToDecimal(data_owner->getST2(id_u).h_u,data_owner->getST2(id_u).h_u_len); //赋值ID_u对应的多集合哈希值
}


search_token Data_User::send_search_token(){
    return st;
}


void Data_User::getSearchRes(std::vector<bool> res,std::string w,std::string pi_w,std::string pi_u,std::string acc){
    //Proof
    std::string x_w = hashToDecimal((unsigned char*)st.h_w.c_str(),SHA_256_SIZE);
    std::string x_u = hashToDecimal((unsigned char*)st.h_u.c_str(),SHA_256_SIZE);
    uint64_t start_time =  timeSinceEpochMillisec();
    quickpower(pi_w,x_w,acN);
    quickpower(pi_u,x_u,acN);
    uint64_t end_time =  timeSinceEpochMillisec();
    std::cout << "********Time for verifying********" << std::endl;
    std::cout << "Total time: " <<end_time - start_time << " ms" << std::endl;
    // if(quickpower(pi_w,x_w,acN) == acc && quickpower(pi_u,x_u,acN) == acc){ //RSA accumulator验证
    //     std::cout<<"------Search result------"<<std::endl;
    //     for(int i=0;i<res.size();i++){
    //         if(res[i] == 1){
    //             std::cout<<"index: "<<i<<"\te.g\t"<<"File id: "<<100-i<<std::endl;
    //         }
    //     }
    // }
}
