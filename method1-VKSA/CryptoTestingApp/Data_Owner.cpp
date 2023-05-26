#include "Data_Owner.h"
#include "../Exceptions/Exceptions.h"

#include <vector>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>

Data_Owner::Data_Owner(){
    secure_p_w = ParameterSet::generate_parameter_set(10, 1, 42);
    secure_p_u = ParameterSet::generate_parameter_set(10, 1, 42);
    RAND_bytes(K_s,ENC_KEY_SIZE);
    //generate sk_u
    sk_u = new PrivateKey(secure_p_u);
    sk_w = new PrivateKey(secure_p_w);

    intervel = 0;
}

Data_Owner::~Data_Owner(){
    //clear.
    ST1.clear();
    I1.clear();
    T_w.clear();
    ST2.clear();
    I2.clear();
    T_u.clear();
    index_w.clear();
    index_u.clear();
}

std::unordered_map<std::string,std::vector<bool>> Data_Owner::loadData(std::string folder_name,int number){
    std::unordered_map<std::string,std::vector<bool>> bitmap_w;

    if(!is_directory(folder_name)){
        throw file_error("could not find folder " + folder_name);
    }

    std::string file_path = folder_name+"/" + "1000-100.txt";
    std::ifstream origin_file(file_path.c_str());
    if(!origin_file.good()){
        throw file_error("could not open files " + file_path);
    }

    std::string line;
    while(getline(origin_file,line)){
        std::stringstream ss(line);
        std::string temp;
        int index = 0;
        std::string keyword;
        std::string number;
        while(getline(ss,temp,'\t')){
            if(index == 0){
                keyword = temp;
                index++;
            }else if(index == 1){
                number = temp;
                index++;
            }else{
                int file = -1;
                if(temp == "0"){
                    file = 0;
                }else if(temp == "1"){
                    file = 1;
                    this->index_w[keyword].push_back(index-2);
                }
                if(file!=-1){
                    bitmap_w[keyword].push_back(file);
                }
                index++;
            }
        }
    }
    return bitmap_w;
}

void Data_Owner::build(){
    //for each w
    build_w();
    //for each id_u
    build_id_u();

}

void Data_Owner::build(Server* server){
    build_w(server);
    build_id_u(server);
    std::cout << "********Time for building ADS********" << std::endl;
    std::cout << "Total time: " <<intervel << " ms" << std::endl;

}

void Data_Owner::build_w(Server* server){
    std::unordered_map<std::string,std::vector<bool>> bitmap_w;
    //load the data
    std::string foldname = "../Enron/Enron_bitmap_w";
    //number of datafile
    int number = 1;
    for(int i=0;i<1;i++){
        bitmap_w = loadData(foldname,0);
        uint64_t start_time = timeSinceEpochMillisec();
        //for each keyword w do:
        for(auto iter = bitmap_w.begin();iter!=bitmap_w.end();iter++){
            std::string w = iter->first;
            // std::cout<<w<<" start.."<<'\t';

            //std::cout<<w<<std::endl;
            std::vector<bool> bitmap = iter->second;
            int c_w = 0;
            //generate st_w
            unsigned char* st_w = (unsigned char*)malloc(SHA_256_SIZE);
            RAND_bytes(st_w,SHA_256_SIZE);
            //generate K_w
            unsigned char* ucw = (unsigned char*)w.c_str();
            unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
            int K_w_length = enc_aes_gcm(ucw,strlen((const char*)ucw),K_s,K_w);
            //print_bytes(K_w,K_w_length);

            //generate l_w,K_w connect to st_w
            unsigned char* l_w = (unsigned char*)malloc(SHA_256_SIZE);
            int l_w_length = 0;
            l_w_length = hash256(K_w,K_w_length,st_w,SHA_256_SIZE,l_w);
            std::string l_w_s = unsignedcharToString(l_w,SHA_256_SIZE);

            //generate C_st_w
            //H2(K_w,st_w)
            unsigned char* C_st_w = (unsigned char*)malloc(l_w_length);
            hash256(K_w,K_w_length,st_w,SHA_256_SIZE,C_st_w);
            unsigned char* zero = (unsigned char*)malloc(l_w_length);
            for(int i=0;i<l_w_length;i++){
                zero[i] = '0';
            }
            Hashxor(C_st_w,zero,SHA_256_SIZE,C_st_w);
            

            //homomor crypto
            const auto compressed_e_w = sk_w->encrypt(bitmap);
            const auto e_w = compressed_e_w.expand();

            //multi hash
            uint64_t start_time1 =  timeSinceEpochMillisec();
            unsigned char* h_w = (unsigned char*)malloc(SHA_256_SIZE);
            std::string input = unsignedcharToString(K_w,K_w_length);
            for(int i=0;i<index_w[iter->first].size();i++){
                unsigned char* temp_res = (unsigned char*)malloc(SHA_256_SIZE);
                std::string hash_input = input + std::to_string(index_w[iter->first][i]);
                unsigned char* message = (unsigned char*)hash_input.c_str();
                hash_sha256(message,hash_input.length(),temp_res);
                if(i == 0){
                    memcpy(h_w,temp_res,SHA_256_SIZE);
                }else{
                    Hashxor(h_w,temp_res,SHA_256_SIZE,h_w);
                }
                message = NULL;
                free(temp_res);
            }
            uint64_t end_time1 =  timeSinceEpochMillisec();
            intervel += end_time1 - start_time1;
            


            //generate ST1[W]
            ST1_value value;
            value.c_w = c_w;
            value.h_w_len = SHA_256_SIZE;
            value.h_w = (unsigned char*)malloc(value.h_w_len);
            memcpy(value.h_w,h_w,value.h_w_len);

            value.st_w = (unsigned char*)malloc(SHA_256_SIZE);
            memcpy(value.st_w,st_w,SHA_256_SIZE);
            value.st_w_len = SHA_256_SIZE;

            ST1[iter->first] = value;
            

            //generate I1[w]
            I1_value value1;
            value1.e_w = e_w;
            value1.C_st_w_len = SHA_256_SIZE;
            value1.C_st_w = (unsigned char*)malloc(SHA_256_SIZE);
            memcpy(value1.C_st_w,C_st_w,SHA_256_SIZE);
            server->getI1Value(std::pair<std::string,I1_value>(l_w_s,value1));
            
            
            //generate T[w]
            T_w_value value2;
            value2.h_w_len = SHA_256_SIZE;
            value2.h_w = (unsigned char*)malloc(value2.h_w_len);
            memcpy(value2.h_w,h_w,value2.h_w_len);
            
            free(K_w);
            free(l_w);
            free(h_w);
            free(zero);
            free(C_st_w);
            free(st_w);
            free(value1.C_st_w);



            // std::cout<<w<<" finished."<<std::endl;

            // std::cout << number << "-th keyword" << std::endl;
            number++;
            // if(number > 0000){
            //     break;
            // }
        }
        uint64_t end_time =  timeSinceEpochMillisec();
        std::cout << "********Time for building Index********" << std::endl;
        std::cout << "Total time: " <<end_time - start_time  << " ms" << std::endl;

    }
    std::cout<<"------build_w finished------"<<std::endl;
}


void Data_Owner::build_id_u(Server* server){
    //set id_u example
    std::unordered_map<std::string,std::vector<bool>> bitmap_id_u;
    std::vector<bool> bitmap1(BITMAP_SIZE,1);
    std::vector<bool> bitmap2(BITMAP_SIZE,0);
    bitmap_id_u["example1"] = bitmap1;
    bitmap_id_u["example2"] = bitmap2;

    for(auto iter=bitmap_id_u.begin();iter!=bitmap_id_u.end();iter++){
        for(int i=0;i<BITMAP_SIZE;i++){
            if(iter->second[i] == 1){
                index_u[iter->first].push_back(i);
            }
        }
    }
    //for each id_u
    for(auto iter = bitmap_id_u.begin();iter!=bitmap_id_u.end();iter++){
        std::string user = iter->first;
        // std::cout<<user<<" start.."<<'\t';

        std::vector<bool> bitmap = iter->second;
        //generate c_u
        int c_u = 0;

        //generate st_u
        unsigned char* st_u = (unsigned char*)malloc(SHA_256_SIZE);
        RAND_bytes(st_u,SHA_256_SIZE);

        //generate K_u
        unsigned char* ucu = (unsigned char*)user.c_str();
        unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
        int K_u_length = enc_aes_gcm(ucu,strlen((const char*)ucu),K_s,K_u);

        //generate l_u
        unsigned char* l_u = (unsigned char*)malloc(SHA_256_SIZE);
        int l_u_length = hash256(K_u,K_u_length,st_u,SHA_256_SIZE,l_u);
        std::string l_u_s = unsignedcharToString(l_u,l_u_length);


        //homomor crypto
        const auto compressed_e_u = sk_u->encrypt(bitmap);
        const auto e_u = compressed_e_u.expand();
        
        //multihash
        unsigned char* h_u = (unsigned char*)malloc(SHA_256_SIZE);
        for(int i=0;i<SHA_256_SIZE;i++){
            h_u[i] = '0';
        }
        std::string input= unsignedcharToString(K_u,K_u_length);
        for(int i=0;i<index_u[iter->first].size();i++){
            unsigned char* temp = (unsigned char*)malloc(SHA_256_SIZE);
            std::string hash_input = input + std::to_string(index_u[iter->first][i]);
            unsigned char* message = (unsigned char*)hash_input.c_str();
            hash_sha256(message,input.length(),temp);
            if(i == 0){
                memcpy(h_u,temp,SHA_256_SIZE);
            }else{
                Hashxor(h_u,temp,SHA_256_SIZE,h_u);
            }
            message = NULL;
            free(temp);
        }

        //generate ST1[u]
        ST2_value value;
        value.c_u = c_u;
        value.h_u = h_u;
        value.h_u_len = SHA_256_SIZE;
        value.st_u = st_u; 
        value.st_u_len = SHA_256_SIZE;
        ST2[iter->first] = value;

        //generate I1[u]
        I2_value value1;
        value1.e_u = e_u;
        server->getI2Value(std::pair<std::string,I2_value>(l_u_s,value1));

        //generate T[u]
        T_u_value value2;
        value2.h_u = h_u;
        value2.h_u_len = SHA_256_SIZE;

        std::cout<<user<<" finished."<<std::endl;
    }
    std::cout<<"------build_id_u finished------"<<std::endl;
}

void Data_Owner::build_id_u(){
    //set id_u example
    std::unordered_map<std::string,std::vector<bool>> bitmap_id_u;
    std::vector<bool> bitmap1(BITMAP_SIZE,1);
    std::vector<bool> bitmap2(BITMAP_SIZE,0);
    bitmap_id_u["example1"] = bitmap1;
    bitmap_id_u["example2"] = bitmap2;

    for(auto iter=bitmap_id_u.begin();iter!=bitmap_id_u.end();iter++){
        for(int i=0;i<BITMAP_SIZE;i++){
            if(iter->second[i] == 1){
                index_u[iter->first].push_back(i);
            }
        }
    }
    //for each id_u
    for(auto iter = bitmap_id_u.begin();iter!=bitmap_id_u.end();iter++){
        std::string user = iter->first;
        std::cout<<user<<" start.."<<'\t';

        std::vector<bool> bitmap = iter->second;
        //generate c_u
        int c_u = 0;

        //generate st_u
        unsigned char* st_u = (unsigned char*)malloc(SHA_256_SIZE);
        RAND_bytes(st_u,SHA_256_SIZE);

        //generate K_u
        unsigned char* ucu = (unsigned char*)user.c_str();
        unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
        int K_u_length = enc_aes_gcm(ucu,strlen((const char*)ucu),K_s,K_u);

        //generate l_u
        unsigned char* l_u = (unsigned char*)malloc(SHA_256_SIZE);
        int l_u_length = hash256(K_u,K_u_length,st_u,SHA_256_SIZE,l_u);
        std::string l_u_s = unsignedcharToString(l_u,l_u_length);


        //homomor crypto
        const auto compressed_e_u = sk_u->encrypt(bitmap);
        const auto e_u = compressed_e_u.expand();
        // //boost serialization
        // std::stringstream ss;
        // boost::archive::text_oarchive oa(ss);
        // oa<<ciphertext;
        // unsigned char* e_u = (unsigned char*)malloc(ss.str().length());
        // int e_u_length = ss.str().length();
        // strcpy((char*)e_u,ss.str().c_str());
        // ss.clear();
        
        //multihash
        unsigned char* h_u = (unsigned char*)malloc(SHA_256_SIZE);
        for(int i=0;i<SHA_256_SIZE;i++){
            h_u[i] = '0';
        }
        std::string input= unsignedcharToString(K_u,K_u_length);
        for(int i=0;i<index_u[iter->first].size();i++){
            unsigned char* temp = (unsigned char*)malloc(SHA_256_SIZE);
            std::string hash_input = input + std::to_string(index_u[iter->first][i]);
            unsigned char* message = (unsigned char*)hash_input.c_str();
            hash_sha256(message,input.length(),temp);
            if(i == 0){
                memcpy(h_u,temp,SHA_256_SIZE);
            }else{
                Hashxor(h_u,temp,SHA_256_SIZE,h_u);
            }
            message = NULL;
            free(temp);
        }

        //generate ST1[u]
        ST2_value value;
        value.c_u = c_u;
        value.h_u = h_u;
        value.h_u_len = SHA_256_SIZE;
        value.st_u = st_u; 
        value.st_u_len = SHA_256_SIZE;
        ST2[iter->first] = value;

        //generate I1[u]
        I2_value value1;
        value1.e_u = e_u;
        I2[l_u_s] = value1;

        //generate T[u]
        T_u_value value2;
        value2.h_u = h_u;
        value2.h_u_len = SHA_256_SIZE;

        std::cout<<user<<" finished."<<std::endl;
    }
    std::cout<<"------build_id_u finished------"<<std::endl;
}

void Data_Owner::build_w(){
    std::unordered_map<std::string,std::vector<bool>> bitmap_w;
    //load the data
    std::string foldname = "../Enron/Enron_bitmap_w";
    //number of datafile
    int number = 1;
    for(int i=0;i<1;i++){
        bitmap_w = loadData(foldname,0);
        //for each keyword w do:
        for(auto iter = bitmap_w.begin();iter!=bitmap_w.end();iter++){
            std::string w = iter->first;
            // std::cout<<w<<" start.."<<'\t';

            //std::cout<<w<<std::endl;
            std::vector<bool> bitmap = iter->second;
            //printBitmap(bitmap);
            int c_w = 0;
            //generate st_w
            unsigned char* st_w = (unsigned char*)malloc(SHA_256_SIZE);
            RAND_bytes(st_w,SHA_256_SIZE);
            //print_bytes(st_w,SHA_256_SIZE);
            //generate K_w
            unsigned char* ucw = (unsigned char*)w.c_str();
            unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
            int K_w_length = enc_aes_gcm(ucw,strlen((const char*)ucw),K_s,K_w);
            //print_bytes(K_w,K_w_length);

            //generate l_w,K_w connect to st_w
            unsigned char* l_w = (unsigned char*)malloc(SHA_256_SIZE);
            int l_w_length = 0;
            l_w_length = hash256(K_w,K_w_length,st_w,SHA_256_SIZE,l_w);
            // if(w == "transfer"){
            //     printf("\n");
            //     print_bytes(st_w,SHA_256_SIZE);
            // }
            std::string l_w_s = unsignedcharToString(l_w,SHA_256_SIZE);

            //generate C_st_w
            //H2(K_w,st_w)
            unsigned char* C_st_w = (unsigned char*)malloc(l_w_length);
            hash256(K_w,K_w_length,st_w,SHA_256_SIZE,C_st_w);
            unsigned char* zero = (unsigned char*)malloc(l_w_length);
            for(int i=0;i<l_w_length;i++){
                zero[i] = '0';
            }
            Hashxor(C_st_w,zero,SHA_256_SIZE,C_st_w);
            

            //homomor crypto
            const auto compressed_e_w = sk_w->encrypt(bitmap);
            // std::cout <<"Before:" << compressed_e_w.size() << std::endl;
            const auto e_w = compressed_e_w.expand();
            // //boost serialization
            // std::stringstream ss;
            // boost::archive::text_oarchive oa(ss);
            // oa<<compressed_ciphertext;
            // long long e_w_length = (long long)ss.str().length();
            // //std::cout<<e_w_length<<std::endl;
            // unsigned char* e_w = (unsigned char*)ss.str().c_str();
            // ss.clear();

            //multi hash
            unsigned char* h_w = (unsigned char*)malloc(SHA_256_SIZE);
            std::string input = unsignedcharToString(K_w,K_w_length);
            for(int i=0;i<index_w[iter->first].size();i++){
                unsigned char* temp_res = (unsigned char*)malloc(SHA_256_SIZE);
                std::string hash_input = input + std::to_string(index_w[iter->first][i]);
                unsigned char* message = (unsigned char*)hash_input.c_str();
                hash_sha256(message,hash_input.length(),temp_res);
                if(i == 0){
                    memcpy(h_w,temp_res,SHA_256_SIZE);
                }else{
                    Hashxor(h_w,temp_res,SHA_256_SIZE,h_w);
                }
                message = NULL;
                free(temp_res);
            }


            //generate ST1[W]
            ST1_value value;
            value.c_w = c_w;
            value.h_w_len = SHA_256_SIZE;
            value.h_w = (unsigned char*)malloc(value.h_w_len);
            memcpy(value.h_w,h_w,value.h_w_len);

            value.st_w = (unsigned char*)malloc(SHA_256_SIZE);
            memcpy(value.st_w,st_w,SHA_256_SIZE);
            value.st_w_len = SHA_256_SIZE;

            ST1[iter->first] = value;
            free(st_w);

            //generate I1[w]
            I1_value value1;
            //value1.e_w_len = e_w_length;
            //value1.e_w = (unsigned char*)malloc(e_w_length);
            //memcpy(value1.e_w,e_w,e_w_length);
            value1.e_w = e_w;
            value1.C_st_w_len = SHA_256_SIZE;
            value1.C_st_w = (unsigned char*)malloc(SHA_256_SIZE);
            memcpy(value1.C_st_w,C_st_w,SHA_256_SIZE);
            I1[l_w_s] = value1;
            
            //generate T[w]
            T_w_value value2;
            value2.h_w_len = SHA_256_SIZE;
            value2.h_w = (unsigned char*)malloc(value2.h_w_len);
            memcpy(value2.h_w,h_w,value2.h_w_len);
            
            free(K_w);
            free(l_w);
            free(h_w);
            free(zero);
            free(C_st_w);
            // std::cout<<w<<" finished."<<std::endl;

            std::cout << number << "-th keyword" << std::endl;
            number++;
            if(number > 4000){
                break;
            }
        }
    }
    std::cout<<"------build_w finished------"<<std::endl;
}

std::unordered_map<std::string,T_w_value> Data_Owner::sendT_w(){
    return T_w;
}
std::unordered_map<std::string,T_u_value> Data_Owner::sendT_u(){
    return T_u;
}
std::unordered_map<std::string,I1_value> Data_Owner::sendI1(){
    return I1;
}
std::unordered_map<std::string,I2_value> Data_Owner::sendI2(){
    return  I2;
}

std::pair<std::string,I1_value> Data_Owner::update_w(std::string w,std::vector<bool> bitmap_w,T_w_value& T_value){
    std::cout<<"------update_w start------"<<std::endl;

    //generate K_w
    unsigned char* ucw = (unsigned char*)w.c_str();
    unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
    int K_w_length = enc_aes_gcm(ucw,strlen((const char*)ucw),K_s,K_w);

    int c_w;
    unsigned char* st_w_cw = (unsigned char*)malloc(SHA_256_SIZE);
    unsigned char* h_w = (unsigned char*)malloc(SHA_256_SIZE);
    if(ST1.find(w) == ST1.end()){
        c_w = -1;
        for(int i=0;i<SHA_256_SIZE;i++){
            h_w[i] = '0';
        }
        for(int i=0;i<SHA_256_SIZE;i++){
            st_w_cw[i] = '0';
        }
    }else{
        c_w = ST1[w].c_w;
        memcpy(st_w_cw,ST1[w].st_w,SHA_256_SIZE);
        memcpy(h_w,ST1[w].h_w,SHA_256_SIZE);
    }

    c_w++;
    unsigned char* new_st_w_cw = (unsigned char*)malloc(SHA_256_SIZE);
    RAND_bytes(new_st_w_cw,SHA_256_SIZE);

    unsigned char* new_l_w_c_w = (unsigned char*)malloc(SHA_256_SIZE);
    int new_l_w_c_w_len = hash256(K_w,K_w_length,new_st_w_cw,SHA_256_SIZE,new_l_w_c_w);
    std::string new_l_w_c_w_s = unsignedcharToString(new_l_w_c_w,SHA_256_SIZE);
    
    unsigned char* temp = (unsigned char*)malloc(SHA_256_SIZE);
    int temp_len = hash256(K_w,K_w_length,new_st_w_cw,SHA_256_SIZE,temp);
    unsigned char* C_st_w = (unsigned char*)malloc(SHA_256_SIZE);
    Hashxor(temp,st_w_cw,SHA_256_SIZE,C_st_w);
    free(temp);

    //useless 
    unsigned char* sk_w_c_w = (unsigned char*)malloc(SHA_256_SIZE);
    std::string strc_w = std::to_string(c_w);
    unsigned char* uc_c_w = (unsigned char*)strc_w.c_str();
    hash256(K_w,K_w_length,uc_c_w,strc_w.length(),sk_w_c_w);
    uc_c_w = NULL;

    //useful
    const auto compressed_e_w = sk_w->encrypt(bitmap_w);
    const auto e_w = compressed_e_w.expand();
    // //boost serialization
    // std::stringstream ss;
    // boost::archive::text_oarchive oa(ss);
    // oa<<ciphertext;
    // unsigned char* e_w_c_w = (unsigned char*)ss.str().c_str();
    // int e_w_length = ss.str().length();
    // ss.clear();

    //update h_w
    unsigned char* res = (unsigned char*)malloc(SHA_256_SIZE);
    getMultiHash(bitmap_w,res,K_w,K_w_length);
    if(isZero(h_w,SHA_256_SIZE)){
        memcpy(h_w,res,SHA_256_SIZE);
    }else{
        Hashxor(h_w,res,SHA_256_SIZE,h_w);
    }
    free(res);

    //ST1[W]
    if(ST1.find(w) != ST1.end()){
        free(ST1[w].h_w);
        free(ST1[w].st_w);
    }
    ST1_value value;
    value.c_w = c_w;
    value.h_w_len = SHA_256_SIZE;
    value.h_w = (unsigned char*)malloc(value.h_w_len);
    memcpy(value.h_w,h_w,value.h_w_len);
    value.st_w_len = SHA_256_SIZE;
    value.st_w = (unsigned char*)malloc(value.st_w_len);
    memcpy(value.st_w,new_st_w_cw,value.st_w_len); 
    ST1[w] = value;

    //I1
    if(I1.find(new_l_w_c_w_s) != I1.end()){
        //free(I1[new_l_w_c_w_s].e_w);
        free(I1[new_l_w_c_w_s].C_st_w);
    }
    I1_value value1;
    //value1.e_w_len = e_w_length;
    //value1.e_w = (unsigned char*)malloc(e_w_length);
    value1.e_w = e_w;
    //memcpy(value1.e_w,e_w_c_w,e_w_length);
    value1.C_st_w_len = SHA_256_SIZE;
    value1.C_st_w = (unsigned char*)malloc(value1.C_st_w_len);
    memcpy(value1.C_st_w,C_st_w,value1.C_st_w_len);
    I1[new_l_w_c_w_s] = value1;

    //T[w]
    if(T_w.find(w) != T_w.end()){
        free(T_w[w].h_w); 
    }
    T_w_value value2;
    value2.h_w_len = SHA_256_SIZE;
    value2.h_w = (unsigned char*)malloc(value2.h_w_len);
    memcpy(value2.h_w,h_w,value2.h_w_len);
    T_value = value2;
    T_w[w] = value2;

    free(h_w);
    free(new_st_w_cw);
    free(C_st_w);
    free(K_w);

    std::cout<<"------update_w finished------"<<std::endl;

    //print_bytes(I1[new_l_w_c_w].e_w,I1[new_l_w_c_w].e_w_len);
    //print_bytes(new_l_w_c_w,SHA_256_SIZE);
    //std::cout<<strlen((char*)new_l_w_c_w)<<std::endl; //is not 32 

    return std::pair<std::string,I1_value>(new_l_w_c_w_s,value1);
}   

std::pair<std::string,I2_value> Data_Owner::update_u(std::string u,std::vector<bool> bitmap_u,T_u_value& T_value){
    std::cout<<"------update_u start------"<<std::endl;
    //generate K_u
    unsigned char* ucu = (unsigned char*)u.c_str();
    unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
    int K_u_length = enc_aes_gcm(ucu,strlen((const char*)ucu),K_s,K_u);

    int c_u;
    unsigned char* st_u = (unsigned char*)malloc(SHA_256_SIZE);
    unsigned char* h_u = (unsigned char*)malloc(SHA_256_SIZE);
    if(ST2.find(u) == ST2.end()){
        c_u = 0;
        RAND_bytes(st_u,SHA_256_SIZE);
        for(int i=0;i<SHA_256_SIZE;i++){
            h_u[i] = '0';
        }
    }else{
        c_u = ST2[u].c_u;
        memcpy(st_u,ST2[u].st_u,SHA_256_SIZE);
        memcpy(h_u,ST2[u].h_u,SHA_256_SIZE);
    }

    unsigned char* l_u =  (unsigned char*)malloc(SHA_256_SIZE);
    hash256(K_u,K_u_length,st_u,SHA_256_SIZE,l_u);
    std::string l_u_s = unsignedcharToString(l_u,SHA_256_SIZE);

    //useless
    unsigned char* sk =  (unsigned char*)malloc(SHA_256_SIZE);
    hash256(K_u,K_u_length,(unsigned char*)std::to_string(c_u).c_str(),std::to_string(c_u).length(),sk);

    //useful
    const auto compressed_e_u = sk_u->encrypt(bitmap_u);
    const auto e_u = compressed_e_u.expand();
    // //boost serialization
    // std::stringstream ss;
    // boost::archive::text_oarchive oa(ss);
    // oa<<ciphertext;
    // unsigned char* e_u = (unsigned char*)ss.str().c_str();
    // int e_u_length = ss.str().length();
    // ss.clear();

    //update h_u
    unsigned char* res = (unsigned char*)malloc(SHA_256_SIZE);
    getMultiHash(bitmap_u,res,K_u,K_u_length);
    if(isZero(h_u,SHA_256_SIZE)){
        memcpy(h_u,res,SHA_256_SIZE);
    }else{
        Hashxor(h_u,res,SHA_256_SIZE,h_u);
    }
    free(res);

    //ST2[u]
    ST2_value value;
    value.c_u = c_u;
    value.h_u_len = SHA_256_SIZE;
    value.h_u = h_u;
    value.st_u_len = SHA_256_SIZE;
    value.st_u = st_u; 
    ST2[u] = value;

    //I2[u]
    I2_value value1;
    //value1.e_u_len = e_u_length;
    //value1.e_u = (unsigned char*)malloc(e_u_length);
    //memcpy(value1.e_u,e_u,e_u_length);
    value1.e_u = e_u;
    I2[l_u_s] = value1;

    //T[u]
    T_u_value value2;
    value2.h_u_len = SHA_256_SIZE;
    value2.h_u = h_u;
    T_value = value2;
    T_u[u] = value2;

    std::cout<<"------update_u finished------"<<std::endl;
    return std::pair<std::string,I2_value>(l_u_s,value1);
}

int Data_Owner::genK_w(unsigned char* ucw,int ucw_len,unsigned char* K_w){
    int K_w_length = enc_aes_gcm(ucw,ucw_len,K_s,K_w);
    return K_w_length;
}

int Data_Owner::genK_u(unsigned char* ucu,int ucu_len,unsigned char* K_u){
    int K_u_length = enc_aes_gcm(ucu,ucu_len,K_s,K_u);
    return K_u_length;
}

ST1_value Data_Owner::getST1(std::string w){
    if(ST1.find(w) != ST1.end()){
        return ST1[w];
    }
}

ST2_value Data_Owner::getST2(std::string id_u){
    if(ST2.find(id_u) != ST2.end()){
        return ST2[id_u];
    }
}


std::vector<bool> Data_Owner::dec_e_w(unsigned char* e_w){
    //genkey
    const PrivateKey sk(secure_p_w);

    std::string e_string = (char*)e_w;
    std::stringstream ss(e_string);
    boost::archive::text_iarchive ia(ss);
    she::EncryptedArray e;
    ia>>e;
    ss.clear();

    std::vector<bool> res = sk.decrypt(e);
    return res;
}

std::vector<bool> Data_Owner::dec_e_u(unsigned char* e_u){
    //genkey
    const PrivateKey sk(secure_p_u);

    std::string e_string = (char*)e_u;
    std::stringstream ss(e_string);
    boost::archive::text_iarchive ia(ss);
    she::EncryptedArray e;
    ia>>e;
    ss.clear();

    std::vector<bool> res = sk.decrypt(e);
    return res;
}




std::vector<bool> Data_Owner::dec_e(she::EncryptedArray e,int Type){
    std::vector<bool> res;
    if(Type == 1){
        res = sk_w->decrypt(e);
    }else if(Type == 2){
        res = sk_u->decrypt(e);
    }
    return res;
}

//after build before update
void Data_Owner::display_bs_w(std::string w){
    for(int i=0;i<index_w[w].size();i++){
        std::cout<<"index: "<<index_w[w][i]<<"\te.g\t"<<"File id: "<<100-index_w[w][i]<<std::endl;
    }
}