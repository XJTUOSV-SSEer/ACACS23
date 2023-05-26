#ifndef CRYPTOENCLAVE_U_H__
#define CRYPTOENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_TEST2_DEFINED__
#define OCALL_TEST2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_test2, (char* encrypted_content, size_t length_content));
#endif
#ifndef OCALL_TEST_DEFINED__
#define OCALL_TEST_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_test, (int* mint, char* mchar, char* mstring, int len));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PRINT_BYTES_DEFINED__
#define OCALL_PRINT_BYTES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_bytes, (unsigned char* ptr, uint32_t len));
#endif
#ifndef OCALL_TRANSFER_ENCRYPTED_ENTRIES_DEFINED__
#define OCALL_TRANSFER_ENCRYPTED_ENTRIES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_transfer_encrypted_entries, (const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size));
#endif
#ifndef OCALL_RETRIEVE_ENCRYPTED_DOC_DEFINED__
#define OCALL_RETRIEVE_ENCRYPTED_DOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_encrypted_doc, (const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len));
#endif
#ifndef OCALL_DEL_ENCRYPTED_DOC_DEFINED__
#define OCALL_DEL_ENCRYPTED_DOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_del_encrypted_doc, (const char* del_id, size_t del_id_len));
#endif
#ifndef OCALL_RETRIEVE_M_C_DEFINED__
#define OCALL_RETRIEVE_M_C_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_M_c, (unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len));
#endif
#ifndef OCALL_DEL_M_C_VALUE_DEFINED__
#define OCALL_DEL_M_C_VALUE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_del_M_c_value, (const unsigned char* _u_prime, size_t _u_prime_size));
#endif
#ifndef OCALL_QUERY_TOKENS_ENTRIES_DEFINED__
#define OCALL_QUERY_TOKENS_ENTRIES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_query_tokens_entries, (const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size));
#endif
#ifndef OCALL_DEC_E_DEFINED__
#define OCALL_DEC_E_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dec_e, (unsigned char* sum_e, unsigned char* res, int dec));
#endif
#ifndef OCALL_SEND_PROOF_RES_DEFINED__
#define OCALL_SEND_PROOF_RES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send_Proof_res, (unsigned char* Proof_res, int len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid, unsigned char* keyF, size_t len);
sgx_status_t ecall_addDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, char* content, int content_length);
sgx_status_t ecall_delDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length);
sgx_status_t ecall_search(sgx_enclave_id_t eid, const char* keyword, size_t len);
sgx_status_t ecall_test(sgx_enclave_id_t eid, char* encrypted_content, size_t length_content);
sgx_status_t ecall_hash_sha256_test(sgx_enclave_id_t eid, unsigned char* message, size_t message_length);
sgx_status_t ecall_get_Proof_ID_u(sgx_enclave_id_t eid, char* ID_u, int id_len, unsigned char* h_u, int h_u_len);
sgx_status_t ecall_get_Proof_w(sgx_enclave_id_t eid, char* w, int w_len, unsigned char* h_w, int h_w_len);
sgx_status_t ecall_Enclave_search(sgx_enclave_id_t eid, char* w, int w_len, char* id_u, int id_u_len, unsigned char* bs_w_out, int bs_w_out_len, unsigned char* bs_u_out, int bs_u_out_len, unsigned char* K_w, int K_w_len, unsigned char* K_u, int K_u_len, int c_w, int c_u);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
