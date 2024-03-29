#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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

#ifndef SESSION_REQUEST_OCALL_DEFINED__
#define SESSION_REQUEST_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, session_request_ocall, (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id));
#endif
#ifndef EXCHANGE_REPORT_OCALL_DEFINED__
#define EXCHANGE_REPORT_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id));
#endif
#ifndef SEND_REQUEST_OCALL_DEFINED__
#define SEND_REQUEST_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, send_request_ocall, (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size));
#endif
#ifndef END_SESSION_OCALL_DEFINED__
#define END_SESSION_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, end_session_ocall, (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
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

sgx_status_t Enclave_test_create_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
sgx_status_t Enclave_test_enclave_to_enclave_call(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
sgx_status_t Enclave_test_message_exchange(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
sgx_status_t Enclave_test_close_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
sgx_status_t Enclave_init(sgx_enclave_id_t eid);
sgx_status_t Enclave_createZeroSecretSharings(sgx_enclave_id_t eid, SS** retval, int factor);
sgx_status_t Enclave_createRandomSecretSharings(sgx_enclave_id_t eid, SS** retval, int factor);
sgx_status_t Enclave_DecryptoSS(sgx_enclave_id_t eid, mpz_t** retval, SS* source, int factor);
sgx_status_t Enclave_DecryptoGA(sgx_enclave_id_t eid, point** retval, mpz_t* source);
sgx_status_t Enclave_getRxy(sgx_enclave_id_t eid, point** retval, const mpz_t* u, const point* beta);
sgx_status_t Enclave_mod(sgx_enclave_id_t eid, mpz_t* r);
sgx_status_t Enclave_hash(sgx_enclave_id_t eid, mpz_t** retval, const char* message, int len);
sgx_status_t Enclave_session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
sgx_status_t Enclave_exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t Enclave_generate_response(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size);
sgx_status_t Enclave_end_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id);
sgx_status_t Enclave_sign_message(sgx_enclave_id_t eid, sign** retval, mpz_t* privateKey, const char* message, const EC* curve);
sgx_status_t Enclave_verifySignature(sgx_enclave_id_t eid, int* retval, const point* publicKey, const char* message, const sign* signature, const EC* curve);
sgx_status_t Enclave_createSS(sgx_enclave_id_t eid, SS** retval, int threshold, int n, mpz_t* secret, mpz_t* modeP);
sgx_status_t Enclave_combiner(sgx_enclave_id_t eid, mpz_t** retval, const DecryptoInfo* secrets, mpz_t* modeP);
sgx_status_t Enclave_scalar_multi(sgx_enclave_id_t eid, point** retval, mpz_t* k, const point* p, const EC* curve);
sgx_status_t Enclave_createPoint(sgx_enclave_id_t eid, point** retval, char* x, char* y);
sgx_status_t Enclave_createEC(sgx_enclave_id_t eid, EC** retval, char* p, char* n, point* G, int a, int b, int h);
sgx_status_t Enclave_inverse_mod(sgx_enclave_id_t eid, mpz_t** retval, const mpz_t* k, const mpz_t* p);
sgx_status_t Enclave_hash_message(sgx_enclave_id_t eid, mpz_t** retval, const char* message, int length, const EC* curve);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
