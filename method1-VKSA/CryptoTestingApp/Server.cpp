#include "Server.h"
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <iostream>
#include "CryptoEnclave_u.h"

Server::Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();
}

Server::~Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();
}

void Server::ReceiveEncDoc(entry *encrypted_doc){
    
    std::string id(encrypted_doc->first.content, encrypted_doc->first.content_length);
    std::string enc_content(encrypted_doc->second.message, encrypted_doc->second.message_length);
    R_Doc.insert(std::pair<std::string,std::string>(id,enc_content));
  
}

//server接受enclave传来的T1,T2
void Server::ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 rand_t *t2_u_arr,rand_t *t2_v_arr,
                                 int pair_count){ 
	for(int indexTest = 0; indexTest < pair_count; indexTest++){

      std::string key1((char*)t1_u_arr[indexTest].content, t1_u_arr[indexTest].content_length);//注意！！！ unsigned char 转换成 char
      std::string value1((char*)t1_v_arr[indexTest].content, t1_v_arr[indexTest].content_length);

      M_I.insert(std::pair<std::string,std::string>(key1,value1)); //插入(u,v)到M_I

      std::string key2((char*)t2_u_arr[indexTest].content, t2_u_arr[indexTest].content_length);
      std::string value2((char*)t2_v_arr[indexTest].content, t2_v_arr[indexTest].content_length);

      M_c.insert(std::pair<std::string,std::string>(key2,value2)); //插入(u',v')到M_C
    }
}

std::string Server::Retrieve_Encrypted_Doc(std::string del_id_str){     //取出             
    return R_Doc.at(del_id_str);
}

void Server::Del_Encrypted_Doc(std::string del_id_str){  //删除
    R_Doc.erase(del_id_str); 
}

std::string Server::Retrieve_M_c(std::string u_prime_str){ //取出
    return M_c.at(u_prime_str);
}

void Server::Del_M_c_value(std::string del_u_prime){ //删除
    M_c.erase(del_u_prime);
}


std::vector<std::string> Server::retrieve_query_results(rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,int pair_count){ //u与Kid

  std::vector<std::string> Res;

  //遍历Q_w
  for(int indexTest = 0; indexTest < pair_count; indexTest++){
      
      //获取u
      std::string u_i((char*)Q_w_u_arr[indexTest].content, Q_w_u_arr[indexTest].content_length);
      //取出Mi[ui]，这是加密后的文件id
      std::string value = M_I.at(u_i);

      unsigned char *key = (unsigned char*)malloc(ENC_KEY_SIZE*sizeof(unsigned char));
      //Q_w_id_arr is kid
      memcpy(key,Q_w_id_arr[indexTest].content,ENC_KEY_SIZE); //取出kid

      int original_len;
	    unsigned char *plaintext =(unsigned char*)malloc((value.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
      //dec for id，id长度为original_len,明文为plaintext
	    original_len= dec_aes_gcm((unsigned char*)value.c_str(),value.size(),key,plaintext);//解密 在Utils里

      //doc_id明文
      std::string doc_i((char*)plaintext,original_len);
      printf("->%s",doc_i.c_str());//输出
      
      Res.push_back(R_Doc.at(doc_i));

      //free
      free(plaintext);
      free(key);


  }

  return Res;

}


//display utilities
void Server::Display_Repo(){

  printf("Display data in Repo\n");
  for ( auto it = R_Doc.begin(); it != R_Doc.end(); ++it ) {
    printf("Cipher\n");
    printf("%s\n", (it->first).c_str());
    print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_I(){

  std::unordered_map<std::string,std::string> ::iterator it;
  printf("Print data in M_I\n");
  for (it = M_I.begin(); it != M_I.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_c(){
  std::unordered_map<std::string,std::string>::iterator it;
  printf("Print data in M_c\n");
  for (it = M_c.begin(); it != M_c.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::getEDB1(std::unordered_map<std::string,I1_value> I1){
  this->EDB1 = I1;
}

void Server::Display_EDB1(){
  for(auto iter = EDB1.begin();iter!=EDB1.end();iter++){
    //print_bytes(iter->first,strlen((char*)iter->first));
  }
}

void Server::getEDB2(std::unordered_map<std::string,I2_value> I2){
  this->EDB2 = I2;
}

void Server::getI1Value(std::pair<std::string,I1_value> value){
  I1_value I1value;
  I1value.C_st_w_len = value.second.C_st_w_len;
  I1value.C_st_w = (unsigned char*)malloc(value.second.C_st_w_len);
  memcpy(I1value.C_st_w,value.second.C_st_w,value.second.C_st_w_len);

  //I1value.e_w_len = value.second.e_w_len;
  //I1value.e_w = (unsigned char*)malloc(value.second.e_w_len);
  //memcpy(I1value.e_w,value.second.e_w,value.second.e_w_len);
  I1value.e_w = value.second.e_w;
  this->EDB1.insert(std::pair<std::string,I1_value>(value.first,I1value));
  //print_bytes(EDB1[value.first].C_st_w,EDB1[value.first].C_st_w_len);
}

void Server::getI2Value(std::pair<std::string,I2_value> value){
  if(EDB2.find(value.first) == EDB2.end()){
    EDB2[value.first] = value.second;
  }else{
    //unsigned char* e1 = (unsigned char*)malloc(value.second.e_u_len);
    //memcpy(e1,value.second.e_u,value.second.e_u_len);
    //unsigned char* e2 = (unsigned char*)malloc(EDB2[value.first].e_u_len);
    //memcpy(e2,EDB2[value.first].e_u,EDB2[value.first].e_u_len);

    //she::EncryptedArray res = homomorAdd(e1,value.second.e_u_len,e2,EDB2[value.first].e_u_len);//>>>>>>>>

    // std::stringstream ss;
    // boost::archive::text_oarchive oa(ss);
    // oa<<res;
    // unsigned char* e_u = (unsigned char*)malloc(ss.str().length());
    // EDB2[value.first].e_u = (unsigned char*)ss.str().c_str();
    // EDB2[value.first].e_u_len = ss.str().length();
    //free(e1);
    //free(e2);
    she::EncryptedArray res = value.second.e_u ^ EDB2[value.first].e_u;
    EDB2[value.first].e_u = res;
  }
}

//send Sum_e_w and e_u;
serverSearchRes Server::getSearch_token(search_token st){
  //w
  she::EncryptedArray sum_e_w;
  std::string l_w_c_w;
  unsigned char* st_w = (unsigned char*)malloc(st.st_w_length);
  memcpy(st_w,st.st_w,st.st_w_length); 
  //search
  for(int i=st.c_w;i>=0;i--){
    unsigned char* l_w_i = (unsigned char*)malloc(SHA_256_SIZE);
    int l_w_i_len = hash256(st.K_w,st.K_w_length,st_w,SHA_256_SIZE,l_w_i);
    //print_bytes(st_w,SHA_256_SIZE);//second st_w is zero
    std::string l_w_i_s = unsignedcharToString(l_w_i,SHA_256_SIZE);
    if(i == st.c_w){
      //record
      l_w_c_w = l_w_i_s;
    }
    //unsigned char* e_w_i = (unsigned char*)malloc(EDB1[l_w_i_s].e_w_len);
    //memcpy(e_w_i,EDB1[l_w_i_s].e_w,EDB1[l_w_i_s].e_w_len);
    she::EncryptedArray e_w_i = EDB1[l_w_i_s].e_w;

    unsigned char* C_st_w = (unsigned char*)malloc(EDB1[l_w_i_s].C_st_w_len); 
    memcpy(C_st_w,EDB1[l_w_i_s].C_st_w,EDB1[l_w_i_s].C_st_w_len); 
    if(i == st.c_w){
      //first time
      sum_e_w = e_w_i;
    }else{
      sum_e_w = sum_e_w ^ e_w_i;
    }

    free(EDB1[l_w_i_s].C_st_w);
    EDB1.erase(l_w_i_s);

    if(isZero(C_st_w,SHA_256_SIZE)){
      break;
    }

    unsigned char* hashres = (unsigned char*)malloc(SHA_256_SIZE);
    int len = hash256(st.K_w,st.K_w_length,st_w,SHA_256_SIZE,hashres);
    Hashxor(hashres,C_st_w,SHA_256_SIZE,st_w);
    free(C_st_w);
    free(hashres);
    free(l_w_i);
  }
  free(st_w);

  I1_value value;

  value.e_w = sum_e_w;

  value.C_st_w_len = SHA_256_SIZE;
  value.C_st_w = (unsigned char*)malloc(SHA_256_SIZE);
  for(int i=0;i<value.C_st_w_len;i++){
    value.C_st_w[i] = '0';
  }

  EDB1[l_w_c_w] = value;

  //id_u
  unsigned char* l_u = (unsigned char*)malloc(SHA_256_SIZE);
  int l_u_len = hash256(st.K_u,st.K_u_length,st.st_u,st.st_u_length,l_u);
  std::string l_u_s = unsignedcharToString(l_u,SHA_256_SIZE);

  //unsigned char* e_u = (unsigned char*)malloc(EDB2[l_u_s].e_u_len);
  //memcpy(e_u,EDB2[l_u_s].e_u,EDB2[l_u_s].e_u_len);
  she::EncryptedArray e_u = EDB2[l_u_s].e_u;
  serverSearchRes res;
  res.e_u = e_u;
  res.Sum_e_w = sum_e_w;
  res.w = charToString(st.w,st.w_len);
  res.id_u = charToString(st.id_u,st.id_u_len);

  free(l_u);
  free(value.C_st_w);

  return res;
}

