#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "sgx_eid.h"
#include "datatypes.h"
#include "../../include/dh_session_protocol.h"
#include "../../include/ECDSA.h"
#include "../../include/SecretSharing.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t test_create_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
uint32_t test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
uint32_t test_message_exchange(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
uint32_t test_close_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
publicKeySS* createSecretSharings(void);
uint32_t session_request(sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
uint32_t generate_response(sgx_enclave_id_t src_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size);
uint32_t end_session(sgx_enclave_id_t src_enclave_id);
sign* sign_message(mpz_t* privateKey, const char* message, const EC* curve);
int verifySignature(const point* publicKey, const char* message, const sign* signature, const EC* curve);
SS* createSS(int threshold, int n, mpz_t* secret, mpz_t* modeP);
mpz_t* combiner(const DecryptoInfo* secrets, mpz_t* modeP);
point* scalar_multi(mpz_t* k, const point* p, const EC* curve);
point* createPoint(char* x, char* y);
EC* createEC(char* p, char* n, point* G, int a, int b, int h);

sgx_status_t SGX_CDECL session_request_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
sgx_status_t SGX_CDECL exchange_report_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t SGX_CDECL send_request_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size);
sgx_status_t SGX_CDECL end_session_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
