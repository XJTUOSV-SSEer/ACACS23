
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
//end for measurement
// uint64_t timeSinceEpochMillisec() {//截取以纪元时间为单位获取当前时间戳，以毫秒为单位

//   using namespace std::chrono;
//   return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
// }


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

// Client* myClient; //extern to separate ocall
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
	// myClient->DecryptDocCollection(REs);
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
	// myClient->DecryptDocCollection(Res);
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

//处理返回结果
void ocall_send_Proof_res(unsigned char* Proof_res,int len,const char* pi_w,const char* pi_u,const char* w,const char* acc){
	std::vector<bool> res;
	for(int i=0;i<len;i++){
		if(Proof_res[i] == '1'){
			res.push_back(1);
		}else if(Proof_res[i] == '0'){
			res.push_back(0);
		}
	}
	data_user2->getSearchRes(res,w,pi_w,pi_u,acc); //返回给ID_u
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
	// myClient= new Client();
	//Server	
	myServer= new Server(); //创建server对象myServer
	//Data_Owner
	data_owner = new Data_Owner(); //创建owner对象data_owner
	//Data_User
	data_user1 = new Data_User("example1"); //创建User对象data_user1
	data_user2 = new Data_User("example2"); //创建User对象data_user2

	//Enclave
	unsigned char KFvalue[ENC_KEY_SIZE]; //文件密钥kF
	// myClient->getKFValue(KFvalue);//赋值KFvalue到myClient对象中的KF，这里KFvalue被KF赋值，KFvalue其实用来生成kw和kc

	//生成Kw kc
	ecall_init(eid,KFvalue,(size_t)ENC_KEY_SIZE); 

	/****************************Build******************************/
	// uint64_t start_time =  timeSinceEpochMillisec();
	data_owner->build(myServer); //Build过程

	//Send acc to enclave
	ecall_get_Acc(eid,data_owner->sendAcc().c_str());
	myServer->getProduct(data_owner->sendProduct()); /////////////////////////

	// uint64_t end_time =  timeSinceEpochMillisec();
	// std::cout << "********Time for building********" << std::endl;
	// std::cout << "Total time: " <<end_time - start_time << std::endl;
	/****************************update******************************/
	//update_w
	std::vector<bool> update_bitmap_w(BITMAP_SIZE,0);
	std::string w = "transfer";
	update_bitmap_w[99] = 1;
	update_bitmap_w[98] = 1;
	T_w_value T_w_temp;
	std::pair<std::string,I1_value> I_1 = data_owner->update_w(w,update_bitmap_w,T_w_temp,myServer);
	//Send I1
	myServer->getI1Value(I_1);
	free(I_1.second.C_st_w);

	//update_w
	std::vector<bool> update_bitmap_w2(BITMAP_SIZE,0);
	update_bitmap_w2[99] = 1;
	update_bitmap_w2[98] = 1;
	T_w_value T_w_temp2;
	I_1 = data_owner->update_w(w,update_bitmap_w2,T_w_temp2,myServer);

	myServer->getI1Value(I_1);
	free(I_1.second.C_st_w);

	//update_u
	std::vector<bool> update_bitmap_u(BITMAP_SIZE,0);
	std::string u = "example2";
	update_bitmap_u[0] = 1;
	update_bitmap_u[1] = 1;
	T_u_value T_u_temp;
	std::pair<std::string,I2_value> I_2 = data_owner->update_u(u,update_bitmap_u,T_u_temp,myServer);
	//Send I2
	myServer->getI2Value(I_2);
	ecall_get_Acc(eid,data_owner->sendAcc().c_str()); //更新Enclave中acc

	/****************************Search******************************/
	uint64_t start_time =  timeSinceEpochMillisec();
	std::string ww = "transfer"; //搜索关键字
	data_user2->Search_request(ww,data_owner);
	serverSearchRes res = myServer->getSearch_token(data_user2->send_search_token());
	//Alternative ways: dec in this way, actually in enclave, because of the "she" Implementation method
	std::vector<bool> bs_w = data_owner->dec_e(res.Sum_e_w,DEC_W); //解密聚合结果Sum_w为bs_w
	std::vector<bool> bs_u = data_owner->dec_e(res.e_u,DEC_U); //解密聚合结果e_u为bs_u

	unsigned char* ucw = (unsigned char*)ww.c_str();
    unsigned char* K_w = (unsigned char*)malloc(strlen((const char*)ucw)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
	int K_w_len = data_owner->genK_w(ucw,ww.length(),K_w);

	unsigned char* ucu = (unsigned char*)data_user2->id_u.c_str();
    unsigned char* K_u = (unsigned char*)malloc(strlen((const char*)ucu)+ AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
	int K_u_len = data_owner->genK_u(ucu,ww.length(),K_u);

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

	/****************************test******************************/
	// //设置docContent
	// docContent *fetch_data;
	// fetch_data = (docContent *)malloc(sizeof(docContent));
	// std::string test1 = "id";
	// std::string test2 = "yangxuyangxuyangxuyangxu";
	// fetch_data->id.id_length = test1.length()+1;
	// fetch_data->content_length = test2.length()+1;
	// fetch_data->content = (char*) malloc(fetch_data->content_length);
	// fetch_data->id.doc_id = (char*)malloc(fetch_data->id.id_length);
	// memcpy(fetch_data->id.doc_id, test1.c_str(),fetch_data->id.id_length);
	// memcpy(fetch_data->content, test2.c_str(),fetch_data->content_length);
	// //设置密文实体
	// entry *encrypted_entry;
	// encrypted_entry = (entry*)malloc(sizeof(entry));
	// encrypted_entry->first.content_length = fetch_data->id.id_length; //add dociId
	// encrypted_entry->first.content = (char*) malloc(fetch_data->id.id_length);
	// encrypted_entry->second.message_length = fetch_data->content_length + AESGCM_MAC_SIZE + AESGCM_IV_SIZE;	//f
	// encrypted_entry->second.message = (char *)malloc(encrypted_entry->second.message_length);
	// //加密操作
	// myClient->EncryptDoc(fetch_data,encrypted_entry);
	// //发送到enclave中
	// ecall_test(eid,encrypted_entry->second.message,encrypted_entry->second.message_length);
	
	// free(fetch_data->content);
	// free(fetch_data->id.doc_id);
	// free(fetch_data);
	
	// free(encrypted_entry->first.content);
	// free(encrypted_entry->second.message);
	// free(encrypted_entry);

	//data_owner->build();

	// K: 2b7e1516 28aed2a6 abf71588 09cf4f3c
	// unsigned char key[] = {0x2b,0x7e,0x15,0x16, 
    //                       0x28,0xae,0xd2,0xa6,
    //                       0xab,0xf7,0x15,0x88,
    //                       0x09,0xcf,0x4f,0x3c};

	// // M: 6bc1bee2 2e409f96 e93d7e11 7393172a Mlen: 128
	// unsigned char message[] = { 0x6b,0xc1,0xbe,0xe2, 
    //                           0x2e,0x40,0x9f,0x96, 
    //                           0xe9,0x3d,0x7e,0x11, 
    //                           0x73,0x93,0x17,0x2a };
	
	// unsigned char res[32] = {0};

	// hash_sha256(message,16,res);
	// //ecall_hash_sha256_test(eid,message,16);

	// data_owner->build();


	//test 同态加密
	// std::stringstream sk_w_stream;
	// data_owner->keyToString(sk_w_stream);
	// const char* sk_w = sk_w_stream.str().c_str();
	// ecall_get_sk_w(eid,sk_w,sk_w_stream.str().length());

	// vector<bool> bitmap1 = {1,1,1,1,1,1};
	// char* w = "keyword";
	// stringstream e_w_stream1;
	// data_owner->EncryptBitmap(w,bitmap1,e_w_stream1);

	// vector<bool> bitmap2 = {0,1,0,1,0,1};
	// char* w2 = "keyword2";
	// stringstream e_w_stream2;
	// data_owner->EncryptBitmap(w2,bitmap1,e_w_stream2);

	// stringstream res;
	// //myServer->homoAdd(e_w_stream1,e_w_stream2,res);

	// ecall_decrypt(eid,res.str().c_str(),res.str().length());


	/****************************actual opreation******************************/
	// printf("Adding doc\n");
	
	// /*** 处理插入操作Update Protocol with op = add */
	// uint64_t start_add_time =  timeSinceEpochMillisec(); //插入操作开始时间
	// for(int i=1;i <= total_file_no; i++){  //total_file_no 多个Update
	// 	//client read a document
	// 	//printf("->%d",i);
	// 	docContent *fetch_data;//原始文档
	// 	fetch_data = (docContent *)malloc(sizeof( docContent));
    //     //获取下一篇doc
	// 	myClient->ReadNextDoc(fetch_data);

	// 	//encrypt and send to Server 
	// 	entry *encrypted_entry;
	// 	encrypted_entry = (entry*)malloc(sizeof(entry));
		
	// 	encrypted_entry->first.content_length = fetch_data->id.id_length; //初始化长度
	// 	encrypted_entry->first.content = (char*) malloc(fetch_data->id.id_length);
	// 	encrypted_entry->second.message_length = fetch_data->content_length + AESGCM_MAC_SIZE + AESGCM_IV_SIZE;	//初始化长度
	// 	encrypted_entry->second.message = (char *)malloc(encrypted_entry->second.message_length);

	// 	//客户端对doc进行加密,结果存入entry实体中
	// 	myClient->EncryptDoc(fetch_data,encrypted_entry);
		
	// 	//send(id,f) to server
	// 	myServer->ReceiveEncDoc(encrypted_entry);
		
	// 	//upload (op,id) to Enclave
	// 	/*****************更新enclave中数据结构*************************/
	// 	//encalve Update所有操作
	// 	//Question: 这个多出一个sgx id的参数是sgx的特性吗？
	// 	ecall_addDoc(eid,fetch_data->id.doc_id,fetch_data->id.id_length,
	// 				fetch_data->content,fetch_data->content_length);
	// 	/**************************************************************/

	// 	//free memory 
	// 	free(fetch_data->content);
	// 	free(fetch_data->id.doc_id);
	// 	free(fetch_data);

	// 	free(encrypted_entry->first.content);
	// 	free(encrypted_entry->second.message);
	// 	free(encrypted_entry);
	// }
	// uint64_t end_add_time =  timeSinceEpochMillisec(); //插入操作结束时间
	// std::cout << "********Time for adding********" << std::endl;
	// std::cout << "Total time:" << end_add_time-start_add_time << " ms" << std::endl;
	// std::cout << "Average time (file):" << (end_add_time-start_add_time)*1.0/total_file_no << " ms" << std::endl;
	// std::cout << "Average time (pair):" << (end_add_time-start_add_time)*1.0/total_pair_no << " ms" << std::endl;

	// //** 处理删除操作Update Protocol with op = del (id)
	// printf("\nDeleting doc\n");
	// uint64_t start_del_time =  timeSinceEpochMillisec(); //删除操作开始时间
	// //docId* delV = new docId[del_no];
	// docId delV_i; //docID:文件ID数据结构
	// for(int del_index=1; del_index <=del_no; del_index++){
	// 	//printf("->%s",delV_i[del_index].doc_id);
	// 	myClient->Del_GivenDocIndex(del_index, &delV_i);
    //     /*****************在enclave中查询关键字*************************/
	// 	ecall_delDoc(eid,delV_i.doc_id,delV_i.id_length); //加入到 d 列表
    //     /**************************************************************/
	// }
	// uint64_t end_del_time =  timeSinceEpochMillisec(); //删除操作结束时间
	// std::cout << "********Time for deleting********" << std::endl;
	// std::cout << "Total time:" << end_del_time-start_del_time << " ms" << std::endl;
	// std::cout << "Average time:" << (end_del_time-start_del_time)*1.0/del_no << " ms" << std::endl;

	// free(delV_i.doc_id);

	
    // /*** 处理搜索操作***/
	// // std::string s_keyword[2]= {"list","clinton"}; 
	// std::string s_keyword[1]= {"bird"};
	// int keyword_count = 1; //查询关键字的数量
	// std::cout << "********Time for searching********" << std::endl;
	// uint64_t total_search_time = 0;
	// for (int s_i = 0; s_i < keyword_count; s_i++){
	// 	std::cout << "Searching ==>" << s_keyword[s_i].c_str() << std::endl;
	// 	// printf("\nSearching ==> %s\n", s_keyword[s_i].c_str());
	// 	uint64_t start_time =  timeSinceEpochMillisec();
	// 	// std::cout << timeSinceEpochMillisec() << std::endl;
    //     /*****************将文档id加入删除list*************************/
	// 	ecall_search(eid, s_keyword[s_i].c_str(), s_keyword[s_i].size());//直接对应第三部分Search的所有流程
    //     /*****************将文档id加入删除list*************************/
    //     uint64_t end_time =  timeSinceEpochMillisec();
	// 	// std::cout << timeSinceEpochMillisec() << std::endl;
	// 	std::cout << "Elapsed time:" << end_time-start_time << " ms"  << std::endl;
	// 	total_search_time += end_time-start_time;
	// }
	// std::cout << "Total time:" << total_search_time << " ms" << std::endl;
	// std::cout << "Average time:" << total_search_time*1.0/keyword_count << " ms" << std::endl;

	// delete myClient;
	// // delete myServer;

	return 0;
}

