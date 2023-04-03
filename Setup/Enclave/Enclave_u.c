#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_test_create_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_create_session_t;

typedef struct ms_test_enclave_to_enclave_call_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_enclave_to_enclave_call_t;

typedef struct ms_test_message_exchange_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_message_exchange_t;

typedef struct ms_test_close_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_close_session_t;

typedef struct ms_createSecretSharings_t {
	publicKeySS* ms_retval;
} ms_createSecretSharings_t;

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_generate_response_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
} ms_generate_response_t;

typedef struct ms_end_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
} ms_end_session_t;

typedef struct ms_sign_message_t {
	sign* ms_retval;
	mpz_t* ms_privateKey;
	const char* ms_message;
	const EC* ms_curve;
} ms_sign_message_t;

typedef struct ms_verifySignature_t {
	int ms_retval;
	const point* ms_publicKey;
	const char* ms_message;
	const sign* ms_signature;
	const EC* ms_curve;
} ms_verifySignature_t;

typedef struct ms_createSS_t {
	SS* ms_retval;
	int ms_threshold;
	int ms_n;
	mpz_t* ms_secret;
	mpz_t* ms_modeP;
} ms_createSS_t;

typedef struct ms_combiner_t {
	mpz_t* ms_retval;
	const DecryptoInfo* ms_secrets;
	mpz_t* ms_modeP;
} ms_combiner_t;

typedef struct ms_scalar_multi_t {
	point* ms_retval;
	mpz_t* ms_k;
	const point* ms_p;
	const EC* ms_curve;
} ms_scalar_multi_t;

typedef struct ms_createPoint_t {
	point* ms_retval;
	char* ms_x;
	char* ms_y;
} ms_createPoint_t;

typedef struct ms_createEC_t {
	EC* ms_retval;
	char* ms_p;
	char* ms_n;
	point* ms_G;
	int ms_a;
	int ms_b;
	int ms_h;
} ms_createEC_t;

typedef struct ms_session_request_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_ocall_t;

typedef struct ms_send_request_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
} ms_send_request_ocall_t;

typedef struct ms_end_session_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_end_session_ocall_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_session_request_ocall(void* pms)
{
	ms_session_request_ocall_t* ms = SGX_CAST(ms_session_request_ocall_t*, pms);
	ms->ms_retval = session_request_ocall(ms->ms_src_enclave_id, ms->ms_dest_enclave_id, ms->ms_dh_msg1, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_src_enclave_id, ms->ms_dest_enclave_id, ms->ms_dh_msg2, ms->ms_dh_msg3, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_send_request_ocall(void* pms)
{
	ms_send_request_ocall_t* ms = SGX_CAST(ms_send_request_ocall_t*, pms);
	ms->ms_retval = send_request_ocall(ms->ms_src_enclave_id, ms->ms_dest_enclave_id, ms->ms_req_message, ms->ms_req_message_size, ms->ms_max_payload_size, ms->ms_resp_message, ms->ms_resp_message_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_end_session_ocall(void* pms)
{
	ms_end_session_ocall_t* ms = SGX_CAST(ms_end_session_ocall_t*, pms);
	ms->ms_retval = end_session_ocall(ms->ms_src_enclave_id, ms->ms_dest_enclave_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_Enclave = {
	10,
	{
		(void*)Enclave_session_request_ocall,
		(void*)Enclave_exchange_report_ocall,
		(void*)Enclave_send_request_ocall,
		(void*)Enclave_end_session_ocall,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t Enclave_test_create_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status;
	ms_test_create_session_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dest_enclave_id = dest_enclave_id;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_test_enclave_to_enclave_call(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status;
	ms_test_enclave_to_enclave_call_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dest_enclave_id = dest_enclave_id;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_test_message_exchange(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status;
	ms_test_message_exchange_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dest_enclave_id = dest_enclave_id;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_test_close_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status;
	ms_test_close_session_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dest_enclave_id = dest_enclave_id;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_createSecretSharings(sgx_enclave_id_t eid, publicKeySS** retval)
{
	sgx_status_t status;
	ms_createSecretSharings_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status;
	ms_session_request_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dh_msg1 = dh_msg1;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status;
	ms_exchange_report_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dh_msg2 = dh_msg2;
	ms.ms_dh_msg3 = dh_msg3;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_generate_response(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
	sgx_status_t status;
	ms_generate_response_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_req_message = req_message;
	ms.ms_req_message_size = req_message_size;
	ms.ms_max_payload_size = max_payload_size;
	ms.ms_resp_message = resp_message;
	ms.ms_resp_message_size = resp_message_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_end_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id)
{
	sgx_status_t status;
	ms_end_session_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_sign_message(sgx_enclave_id_t eid, sign** retval, mpz_t* privateKey, const char* message, const EC* curve)
{
	sgx_status_t status;
	ms_sign_message_t ms;
	ms.ms_privateKey = privateKey;
	ms.ms_message = message;
	ms.ms_curve = curve;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_verifySignature(sgx_enclave_id_t eid, int* retval, const point* publicKey, const char* message, const sign* signature, const EC* curve)
{
	sgx_status_t status;
	ms_verifySignature_t ms;
	ms.ms_publicKey = publicKey;
	ms.ms_message = message;
	ms.ms_signature = signature;
	ms.ms_curve = curve;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_createSS(sgx_enclave_id_t eid, SS** retval, int threshold, int n, mpz_t* secret, mpz_t* modeP)
{
	sgx_status_t status;
	ms_createSS_t ms;
	ms.ms_threshold = threshold;
	ms.ms_n = n;
	ms.ms_secret = secret;
	ms.ms_modeP = modeP;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_combiner(sgx_enclave_id_t eid, mpz_t** retval, const DecryptoInfo* secrets, mpz_t* modeP)
{
	sgx_status_t status;
	ms_combiner_t ms;
	ms.ms_secrets = secrets;
	ms.ms_modeP = modeP;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_scalar_multi(sgx_enclave_id_t eid, point** retval, mpz_t* k, const point* p, const EC* curve)
{
	sgx_status_t status;
	ms_scalar_multi_t ms;
	ms.ms_k = k;
	ms.ms_p = p;
	ms.ms_curve = curve;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_createPoint(sgx_enclave_id_t eid, point** retval, char* x, char* y)
{
	sgx_status_t status;
	ms_createPoint_t ms;
	ms.ms_x = x;
	ms.ms_y = y;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave_createEC(sgx_enclave_id_t eid, EC** retval, char* p, char* n, point* G, int a, int b, int h)
{
	sgx_status_t status;
	ms_createEC_t ms;
	ms.ms_p = p;
	ms.ms_n = n;
	ms.ms_G = G;
	ms.ms_a = a;
	ms.ms_b = b;
	ms.ms_h = h;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

