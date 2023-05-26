
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/data_type.h"
#include "Server.h"
#include "Client.h"
#include "Data_Owner.h"
#include "Data_User.h"
#include "Utils.h"

//for measurement
#include <cstdint>
#include <chrono>
#include <iostream>
// uint64_t timeSinceEpochMillisec() {//截取以纪元时间为单位获取当前时间戳，以毫秒为单位

//   using namespace std::chrono;
//   return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
// }
// //end for measurement


#define ENCLAVE_FILE "CryptoEnclave.signed.so"

// int total_file_no = (int)100000;//50000;//100000
// int total_pair_no = (int)600000;//50000;//100000
// int del_no = (int)0;//10000;//10000;

/* 	Note 1: Enclave only recognises direct pointer with count*size, where count is the number of elements in the array, and size is the size of each element
		other further pointers of pointers should have fixed max length of array to eliminate ambiguity to Enclave (by using pointer [max_buf]).
	Note 2: In outcall, passing pointer [out] can only be modified/changed in the direct .cpp class declaring the ocall function.
	Note 3: If it is an int pointer pointing to a number-> using size=sizeof(int) to declare the size of the int pointer. That will be a larger range than using size_t in ocall
	Note 4: ensure when using openssl and sgxcrypto, plaintext data should be more lengthy than 4-5 characters; (each content in raw_doc should have lengthy characters)
			otherwise, random noise/padding will be auto added.
	Note 5: convert to int or length needs to total_filecome with pre-define length;otherwise, following random bytes can occur.

	memory leak note: 
	1-declare all temp variable outside forloop
	2-all func should return void, pass pointer to callee; caller should init mem and free pointer
	3-use const as input parameter in funcs if any variable is not changed 
	4-re-view both client/server in outside regarding above leak,
		 (docContent fetch_data = myClient->ReadNextDoc();, 

			//free memory 
			free(fetch_data.content);
			free(fetch_data.id.doc_id);)
	5-struct should use constructor and destructor (later)
	6-should use tool to check mem valgrind --leak-check=yes to test add function to see whether memory usage/leak before and after
	7-run with prerelease mode
	8-re generate new list test, but without using the list inside
 */

Client* myClient; //extern to separate ocall
Server* myServer; //extern to separate ocall
Data_Owner* data_owner;
Data_User* data_user2;
Data_User* data_user1;

void ocall_print_string(const char *str) {
    printf("%s\n", str);
}

void ocall_print_bytes(unsigned char* ptr,uint32_t len){
for (uint32_t i = 0; i < len; i++) {
    printf("%x ", *(ptr + i));
  }
  printf("\n");
}

void ocall_test(int* mint,char* mchar,char* mstring,int len) {
	//encrypt and send to Ser
    printf("int1为%d",mint[0]);
    printf("char1为%c",mchar[0]);
    printf("string1为%s",mstring);
}
void ocall_test2(char* encrypted_content, size_t length_content){
	std::string res(encrypted_content,length_content);
	std::vector<std::string> REs;
	REs.push_back(res); 
	myClient->DecryptDocCollection(REs);
}

//server接受enclave传来的T1,T2
void ocall_transfer_encrypted_entries(const void *_t1_u_arr,
									  const void *_t1_v_arr, 
									  const void *_t2_u_arr,
									  const void *_t2_v_arr,
									  int pair_count, int rand_size){

	myServer->ReceiveTransactions(
								(rand_t *)_t1_u_arr,(rand_t *)_t1_v_arr,
								(rand_t *)_t2_u_arr,(rand_t *)_t2_v_arr,
								pair_count);

}


void ocall_retrieve_encrypted_doc(const char *del_id, size_t del_id_len, 
                                  unsigned char *encrypted_content, size_t maxLen,
                                  int *length_content, size_t int_size){
								  
	std::string del_id_str(del_id,del_id_len);	
	std::string encrypted_entry = myServer->Retrieve_Encrypted_Doc(del_id_str);
    *length_content = (int)encrypted_entry.size();
	//later double check *length_content exceeds maxLen
    memcpy(encrypted_content, (unsigned char*)encrypted_entry.c_str(),encrypted_entry.size());
}

void ocall_del_encrypted_doc(const char *del_id, size_t del_id_len){
	std::string del_id_str(del_id,del_id_len);
	myServer->Del_Encrypted_Doc(del_id_str);
}

void ocall_retrieve_M_c(unsigned char * _u_prime, size_t _u_prime_size,
                              unsigned char *_v_prime, size_t maxLen,
                              int *_v_prime_size, size_t int_len){

	std::string u_prime_str((char*)_u_prime,_u_prime_size);
	std::string v_prime_str = myServer->Retrieve_M_c(u_prime_str);

	*_v_prime_size = (int)v_prime_str.size(); 
	memcpy(_v_prime,(unsigned char*)v_prime_str.c_str(),v_prime_str.size());

}

void ocall_del_M_c_value(const unsigned char *_u_prime, size_t _u_prime_size){

	std::string del_u_prime((char*)_u_prime,_u_prime_size);
	myServer->Del_M_c_value(del_u_prime);
}

void ocall_query_tokens_entries(const void *Q_w_u_arr,
                               const void *Q_w_id_arr,
                               int pair_count, int rand_size){
	
	std::vector<std::string> Res;
	Res = myServer->retrieve_query_results(
								(rand_t *)Q_w_u_arr,(rand_t *)Q_w_id_arr,
								pair_count);
	
	//give to Client for decryption
	myClient->DecryptDocCollection(Res);
}

//without release the res space
void ocall_dec_e(unsigned char* sum_e,unsigned char* res,int dec){
	std::vector<bool> bs;
	if(dec == 1){
		bs = data_owner->dec_e_w(sum_e);
	}else if(dec == 2){
		bs = data_owner->dec_e_u(sum_e);
	}
	res = (unsigned char*)malloc(bs.size());
	for(int i=0;i<bs.size();i++){
		if(bs[i] == 1){
			res[i] = '1';
		}else if(bs[i] == 0){
			res[i] = '0';
		}
	}
}

void ocall_send_Proof_res(unsigned char* Proof_res,int len){
	std::vector<bool> res;
	for(int i=0;i<len;i++){
		if(Proof_res[i] == '1'){
			res.push_back(1);
		}else if(Proof_res[i] == '0'){
			res.push_back(0);
		}
	}
	//data_user2->getSearchRes(res);
}

//main func
int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid; //sgx id
	sgx_status_t ret; //sgx状态类型
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;

	/********************创建enclave环境****************************/
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL); //eid
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}
	/**************************************************************/

	/* Setup Protocol*/
	//Client
	myClient= new Client();
	//Server	
	myServer= new Server();
	//Data_Owner
	data_owner = new Data_Owner(); 
	//Data_User
	data_user1 = new Data_User("example1");
	data_user2 = new Data_User("example2");

	//Enclave
	unsigned char KFvalue[ENC_KEY_SIZE]; //文件密钥kF
	myClient->getKFValue(KFvalue);//赋值KFvalue到myClient对象中的KF，这里KFvalue被KF赋值，KFvalue其实用来生成kw和kc

	//生成Kw kc
	ecall_init(eid,KFvalue,(size_t)ENC_KEY_SIZE); 

	/****************************Build******************************/
	data_owner->build(myServer); //>>>>>>>>

	// //Send I1, I2 to server
	// myServer->getEDB1(data_owner->sendI1());
	// myServer->getEDB2(data_owner->sendI2());
	//Send T_w,T_ID_u to enclave
	std::unordered_map<std::string,T_w_value> T_w = data_owner->sendT_w();
	
	for(auto iter = T_w.begin();iter!=T_w.end();iter++){
		char* w = (char*)iter->first.c_str();
		int w_len = iter->first.length();
		ecall_get_Proof_w(
			eid,
			w,w_len,
			iter->second.h_w,iter->second.h_w_len
		);
	}

	std::unordered_map<std::string,T_u_value> T_u = data_owner->sendT_u();
	for(auto iter = T_u.begin();iter!=T_u.end();iter++){
		char* ID_u = (char*)iter->first.c_str();
		int ID_u_len = iter->first.length();
		ecall_get_Proof_ID_u(
			eid,
			ID_u,ID_u_len,
			iter->second.h_u,iter->second.h_u_len
		);
	}

	/****************************update******************************/
	//update_w
	std::vector<bool> update_bitmap_w(BITMAP_SIZE,0);
	std::string w = "transfer";
	update_bitmap_w[99] = 1;
	update_bitmap_w[98] = 1;
	T_w_value T_w_temp;
	std::pair<std::string,I1_value> I_1 = data_owner->update_w(w,update_bitmap_w,T_w_temp);
	//print_bytes(I_1.first,strlen((char*)I_1.first));
	ecall_get_Proof_w(
		eid,
		(char*)w.c_str(),w.length(),
		T_w_temp.h_w,T_w_temp.h_w_len
	);
	//Send I1
	myServer->getI1Value(I_1);
	free(I_1.second.C_st_w);

	std::vector<bool> update_bitmap_w2(BITMAP_SIZE,0);
	update_bitmap_w2[99] = 1;
	update_bitmap_w2[98] = 1;
	T_w_value T_w_temp2;
	I_1 = data_owner->update_w(w,update_bitmap_w2,T_w_temp2);
	ecall_get_Proof_w(
		eid,
		(char*)w.c_str(),w.length(),
		T_w_temp2.h_w,T_w_temp2.h_w_len
	);
	myServer->getI1Value(I_1);
	free(I_1.second.C_st_w);

	//update_u
	std::vector<bool> update_bitmap_u(BITMAP_SIZE,0);
	std::string u = "example2";
	update_bitmap_u[0] = 1;
	update_bitmap_u[1] = 1;
	T_u_value T_u_temp;
	std::pair<std::string,I2_value> I_2 = data_owner->update_u(u,update_bitmap_u,T_u_temp);
	ecall_get_Proof_ID_u(
		eid,
		(char*)u.c_str(),u.length(),
		T_u_temp.h_u,T_u_temp.h_u_len
	);
	//Send I2
	myServer->getI2Value(I_2);

	/****************************Search******************************/
	uint64_t start_time =  timeSinceEpochMillisec();
	std::string ww = "transfer";
	data_user2->Search_request(ww,data_owner);
	serverSearchRes res = myServer->getSearch_token(data_user2->send_search_token());
	//Alternative ways: dec in this way, actually in enclave, because of the "she" Implementation method
	std::vector<bool> bs_w = data_owner->dec_e(res.Sum_e_w,DEC_W); 
	std::vector<bool> bs_u = data_owner->dec_e(res.e_u,DEC_U);

	unsigned char* ucw = (unsigned char*)ww.c_str();
    unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
	int K_w_len = data_owner->genK_w(ucw,w.length(),K_w);

	unsigned char* ucu = (unsigned char*)data_user2->id_u.c_str();
    unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
	int K_u_len = data_owner->genK_u(ucu,w.length(),K_u);

	unsigned char* bs_w_out = bitmap_tranfer(bs_w);
	unsigned char* bs_u_out = bitmap_tranfer(bs_u);
	//data_user2->getSearchRes(bs_w);
	//data_user2->getSearchRes(bs_u);

	ecall_Enclave_search(eid,
		(char*)res.w.c_str(),res.w.length(),
		(char*)res.id_u.c_str(),res.id_u.length(),
		bs_w_out,BITMAP_SIZE,
		bs_u_out,BITMAP_SIZE,
		K_w,K_w_len,
		K_u,K_u_len,
		data_owner->getST1(ww).c_w,
		data_owner->getST2(data_user2->id_u).c_u
	);

	free(bs_w_out);
	free(bs_u_out);
	uint64_t end_time =  timeSinceEpochMillisec();
    std::cout << "********Time for search********" << std::endl;
    std::cout << "Total time: " <<end_time - start_time << " ms" << std::endl;


	return 0;
}

