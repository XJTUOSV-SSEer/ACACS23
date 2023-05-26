#ifndef CRYPTOENCLAVE_T_H__
#define CRYPTOENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init(unsigned char* keyF, size_t len);
void ecall_addDoc(char* doc_id, size_t id_length, char* content, int content_length);
void ecall_delDoc(char* doc_id, size_t id_length);
void ecall_search(const char* keyword, size_t len);
void ecall_test(char* encrypted_content, size_t length_content);
void ecall_hash_sha256_test(unsigned char* message, size_t message_length);
void ecall_get_Proof_ID_u(char* ID_u, int id_len, unsigned char* h_u, int h_u_len);
void ecall_get_Proof_w(char* w, int w_len, unsigned char* h_w, int h_w_len);
void ecall_Enclave_search(char* w, int w_len, char* id_u, int id_u_len, unsigned char* bs_w_out, int bs_w_out_len, unsigned char* bs_u_out, int bs_u_out_len, unsigned char* K_w, int K_w_len, unsigned char* K_u, int K_u_len, int c_w, int c_u);

sgx_status_t SGX_CDECL ocall_test2(char* encrypted_content, size_t length_content);
sgx_status_t SGX_CDECL ocall_test(int* mint, char* mchar, char* mstring, int len);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_bytes(unsigned char* ptr, uint32_t len);
sgx_status_t SGX_CDECL ocall_transfer_encrypted_entries(const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_retrieve_encrypted_doc(const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_encrypted_doc(const char* del_id, size_t del_id_len);
sgx_status_t SGX_CDECL ocall_retrieve_M_c(unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_M_c_value(const unsigned char* _u_prime, size_t _u_prime_size);
sgx_status_t SGX_CDECL ocall_query_tokens_entries(const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_dec_e(unsigned char* sum_e, unsigned char* res, int dec);
sgx_status_t SGX_CDECL ocall_send_Proof_res(unsigned char* Proof_res, int len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
