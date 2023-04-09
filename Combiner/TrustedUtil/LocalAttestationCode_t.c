#include "LocalAttestationCode_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

typedef struct ms_inverse_mod_t {
	mpz_t* ms_retval;
	const mpz_t* ms_k;
	const mpz_t* ms_p;
} ms_inverse_mod_t;

typedef struct ms_hash_message_t {
	mpz_t* ms_retval;
	const char* ms_message;
	int ms_length;
	const EC* ms_curve;
} ms_hash_message_t;

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

static sgx_status_t SGX_CDECL sgx_session_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_session_request_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_session_request_t* ms = SGX_CAST(ms_session_request_t*, pms);
	ms_session_request_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_session_request_t), ms, sizeof(ms_session_request_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg1_t* _tmp_dh_msg1 = __in_ms.ms_dh_msg1;
	size_t _len_dh_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_dh_msg1 = NULL;
	uint32_t* _tmp_session_id = __in_ms.ms_session_id;
	size_t _len_session_id = sizeof(uint32_t);
	uint32_t* _in_session_id = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_dh_msg1, _len_dh_msg1);
	CHECK_UNIQUE_POINTER(_tmp_session_id, _len_session_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_msg1 != NULL && _len_dh_msg1 != 0) {
		if ((_in_dh_msg1 = (sgx_dh_msg1_t*)malloc(_len_dh_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg1, 0, _len_dh_msg1);
	}
	if (_tmp_session_id != NULL && _len_session_id != 0) {
		if ( _len_session_id % sizeof(*_tmp_session_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_session_id = (uint32_t*)malloc(_len_session_id)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_session_id, 0, _len_session_id);
	}
	_in_retval = session_request(__in_ms.ms_src_enclave_id, _in_dh_msg1, _in_session_id);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_dh_msg1) {
		if (memcpy_verw_s(_tmp_dh_msg1, _len_dh_msg1, _in_dh_msg1, _len_dh_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_session_id) {
		if (memcpy_verw_s(_tmp_session_id, _len_session_id, _in_session_id, _len_session_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_msg1) free(_in_dh_msg1);
	if (_in_session_id) free(_in_session_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_exchange_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_exchange_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_exchange_report_t* ms = SGX_CAST(ms_exchange_report_t*, pms);
	ms_exchange_report_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_exchange_report_t), ms, sizeof(ms_exchange_report_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg2_t* _tmp_dh_msg2 = __in_ms.ms_dh_msg2;
	size_t _len_dh_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_dh_msg2 = NULL;
	sgx_dh_msg3_t* _tmp_dh_msg3 = __in_ms.ms_dh_msg3;
	size_t _len_dh_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_dh_msg3 = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_dh_msg2, _len_dh_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg3, _len_dh_msg3);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_msg2 != NULL && _len_dh_msg2 != 0) {
		_in_dh_msg2 = (sgx_dh_msg2_t*)malloc(_len_dh_msg2);
		if (_in_dh_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dh_msg2, _len_dh_msg2, _tmp_dh_msg2, _len_dh_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dh_msg3 != NULL && _len_dh_msg3 != 0) {
		if ((_in_dh_msg3 = (sgx_dh_msg3_t*)malloc(_len_dh_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg3, 0, _len_dh_msg3);
	}
	_in_retval = exchange_report(__in_ms.ms_src_enclave_id, _in_dh_msg2, _in_dh_msg3, __in_ms.ms_session_id);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_dh_msg3) {
		if (memcpy_verw_s(_tmp_dh_msg3, _len_dh_msg3, _in_dh_msg3, _len_dh_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_msg2) free(_in_dh_msg2);
	if (_in_dh_msg3) free(_in_dh_msg3);
	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_response(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_response_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_response_t* ms = SGX_CAST(ms_generate_response_t*, pms);
	ms_generate_response_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_generate_response_t), ms, sizeof(ms_generate_response_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	secure_message_t* _tmp_req_message = __in_ms.ms_req_message;
	size_t _tmp_req_message_size = __in_ms.ms_req_message_size;
	size_t _len_req_message = _tmp_req_message_size;
	secure_message_t* _in_req_message = NULL;
	secure_message_t* _tmp_resp_message = __in_ms.ms_resp_message;
	size_t _tmp_resp_message_size = __in_ms.ms_resp_message_size;
	size_t _len_resp_message = _tmp_resp_message_size;
	secure_message_t* _in_resp_message = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_req_message, _len_req_message);
	CHECK_UNIQUE_POINTER(_tmp_resp_message, _len_resp_message);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_req_message != NULL && _len_req_message != 0) {
		_in_req_message = (secure_message_t*)malloc(_len_req_message);
		if (_in_req_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_req_message, _len_req_message, _tmp_req_message, _len_req_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_resp_message != NULL && _len_resp_message != 0) {
		if ((_in_resp_message = (secure_message_t*)malloc(_len_resp_message)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_resp_message, 0, _len_resp_message);
	}
	_in_retval = generate_response(__in_ms.ms_src_enclave_id, _in_req_message, _tmp_req_message_size, __in_ms.ms_max_payload_size, _in_resp_message, _tmp_resp_message_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_resp_message) {
		if (memcpy_verw_s(_tmp_resp_message, _len_resp_message, _in_resp_message, _len_resp_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_req_message) free(_in_req_message);
	if (_in_resp_message) free(_in_resp_message);
	return status;
}

static sgx_status_t SGX_CDECL sgx_end_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_end_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_end_session_t* ms = SGX_CAST(ms_end_session_t*, pms);
	ms_end_session_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_end_session_t), ms, sizeof(ms_end_session_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint32_t _in_retval;


	_in_retval = end_session(__in_ms.ms_src_enclave_id);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_sign_message(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sign_message_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sign_message_t* ms = SGX_CAST(ms_sign_message_t*, pms);
	ms_sign_message_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sign_message_t), ms, sizeof(ms_sign_message_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	mpz_t* _tmp_privateKey = __in_ms.ms_privateKey;
	const char* _tmp_message = __in_ms.ms_message;
	const EC* _tmp_curve = __in_ms.ms_curve;
	sign* _in_retval;


	_in_retval = sign_message(_tmp_privateKey, (const char*)_tmp_message, (const EC*)_tmp_curve);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_verifySignature(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verifySignature_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_verifySignature_t* ms = SGX_CAST(ms_verifySignature_t*, pms);
	ms_verifySignature_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_verifySignature_t), ms, sizeof(ms_verifySignature_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const point* _tmp_publicKey = __in_ms.ms_publicKey;
	const char* _tmp_message = __in_ms.ms_message;
	const sign* _tmp_signature = __in_ms.ms_signature;
	const EC* _tmp_curve = __in_ms.ms_curve;
	int _in_retval;


	_in_retval = verifySignature((const point*)_tmp_publicKey, (const char*)_tmp_message, (const sign*)_tmp_signature, (const EC*)_tmp_curve);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_createSS(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createSS_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createSS_t* ms = SGX_CAST(ms_createSS_t*, pms);
	ms_createSS_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_createSS_t), ms, sizeof(ms_createSS_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	mpz_t* _tmp_secret = __in_ms.ms_secret;
	mpz_t* _tmp_modeP = __in_ms.ms_modeP;
	SS* _in_retval;


	_in_retval = createSS(__in_ms.ms_threshold, __in_ms.ms_n, _tmp_secret, _tmp_modeP);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_combiner(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_combiner_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_combiner_t* ms = SGX_CAST(ms_combiner_t*, pms);
	ms_combiner_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_combiner_t), ms, sizeof(ms_combiner_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const DecryptoInfo* _tmp_secrets = __in_ms.ms_secrets;
	mpz_t* _tmp_modeP = __in_ms.ms_modeP;
	mpz_t* _in_retval;


	_in_retval = combiner((const DecryptoInfo*)_tmp_secrets, _tmp_modeP);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_scalar_multi(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_scalar_multi_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_scalar_multi_t* ms = SGX_CAST(ms_scalar_multi_t*, pms);
	ms_scalar_multi_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_scalar_multi_t), ms, sizeof(ms_scalar_multi_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	mpz_t* _tmp_k = __in_ms.ms_k;
	const point* _tmp_p = __in_ms.ms_p;
	const EC* _tmp_curve = __in_ms.ms_curve;
	point* _in_retval;


	_in_retval = scalar_multi(_tmp_k, (const point*)_tmp_p, (const EC*)_tmp_curve);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_createPoint(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createPoint_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createPoint_t* ms = SGX_CAST(ms_createPoint_t*, pms);
	ms_createPoint_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_createPoint_t), ms, sizeof(ms_createPoint_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_x = __in_ms.ms_x;
	char* _tmp_y = __in_ms.ms_y;
	point* _in_retval;


	_in_retval = createPoint(_tmp_x, _tmp_y);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_createEC(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createEC_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createEC_t* ms = SGX_CAST(ms_createEC_t*, pms);
	ms_createEC_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_createEC_t), ms, sizeof(ms_createEC_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_p = __in_ms.ms_p;
	char* _tmp_n = __in_ms.ms_n;
	point* _tmp_G = __in_ms.ms_G;
	EC* _in_retval;


	_in_retval = createEC(_tmp_p, _tmp_n, _tmp_G, __in_ms.ms_a, __in_ms.ms_b, __in_ms.ms_h);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_inverse_mod(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_inverse_mod_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_inverse_mod_t* ms = SGX_CAST(ms_inverse_mod_t*, pms);
	ms_inverse_mod_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_inverse_mod_t), ms, sizeof(ms_inverse_mod_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const mpz_t* _tmp_k = __in_ms.ms_k;
	const mpz_t* _tmp_p = __in_ms.ms_p;
	mpz_t* _in_retval;


	_in_retval = inverse_mod((const mpz_t*)_tmp_k, (const mpz_t*)_tmp_p);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_hash_message(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_hash_message_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_hash_message_t* ms = SGX_CAST(ms_hash_message_t*, pms);
	ms_hash_message_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_hash_message_t), ms, sizeof(ms_hash_message_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_message = __in_ms.ms_message;
	const EC* _tmp_curve = __in_ms.ms_curve;
	mpz_t* _in_retval;


	_in_retval = hash_message((const char*)_tmp_message, __in_ms.ms_length, (const EC*)_tmp_curve);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[13];
} g_ecall_table = {
	13,
	{
		{(void*)(uintptr_t)sgx_session_request, 0, 0},
		{(void*)(uintptr_t)sgx_exchange_report, 0, 0},
		{(void*)(uintptr_t)sgx_generate_response, 0, 0},
		{(void*)(uintptr_t)sgx_end_session, 0, 0},
		{(void*)(uintptr_t)sgx_sign_message, 0, 0},
		{(void*)(uintptr_t)sgx_verifySignature, 0, 0},
		{(void*)(uintptr_t)sgx_createSS, 0, 0},
		{(void*)(uintptr_t)sgx_combiner, 0, 0},
		{(void*)(uintptr_t)sgx_scalar_multi, 0, 0},
		{(void*)(uintptr_t)sgx_createPoint, 0, 0},
		{(void*)(uintptr_t)sgx_createEC, 0, 0},
		{(void*)(uintptr_t)sgx_inverse_mod, 0, 0},
		{(void*)(uintptr_t)sgx_hash_message, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][13];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL session_request_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg1 = sizeof(sgx_dh_msg1_t);
	size_t _len_session_id = sizeof(uint32_t);

	ms_session_request_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_session_request_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg1 = NULL;
	void *__tmp_session_id = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);
	CHECK_ENCLAVE_POINTER(session_id, _len_session_id);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg1 != NULL) ? _len_dh_msg1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (session_id != NULL) ? _len_session_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_session_request_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_session_request_ocall_t));
	ocalloc_size -= sizeof(ms_session_request_ocall_t);

	if (memcpy_verw_s(&ms->ms_src_enclave_id, sizeof(ms->ms_src_enclave_id), &src_enclave_id, sizeof(src_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_dest_enclave_id, sizeof(ms->ms_dest_enclave_id), &dest_enclave_id, sizeof(dest_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dh_msg1 != NULL) {
		if (memcpy_verw_s(&ms->ms_dh_msg1, sizeof(sgx_dh_msg1_t*), &__tmp, sizeof(sgx_dh_msg1_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dh_msg1 = __tmp;
		memset_verw(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}

	if (session_id != NULL) {
		if (memcpy_verw_s(&ms->ms_session_id, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_session_id = __tmp;
		if (_len_session_id % sizeof(*session_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_session_id, 0, _len_session_id);
		__tmp = (void *)((size_t)__tmp + _len_session_id);
		ocalloc_size -= _len_session_id;
	} else {
		ms->ms_session_id = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (session_id) {
			if (memcpy_s((void*)session_id, _len_session_id, __tmp_session_id, _len_session_id)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = sizeof(sgx_dh_msg2_t);
	size_t _len_dh_msg3 = sizeof(sgx_dh_msg3_t);

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg2 != NULL) ? _len_dh_msg2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg3 != NULL) ? _len_dh_msg3 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	if (memcpy_verw_s(&ms->ms_src_enclave_id, sizeof(ms->ms_src_enclave_id), &src_enclave_id, sizeof(src_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_dest_enclave_id, sizeof(ms->ms_dest_enclave_id), &dest_enclave_id, sizeof(dest_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dh_msg2 != NULL) {
		if (memcpy_verw_s(&ms->ms_dh_msg2, sizeof(sgx_dh_msg2_t*), &__tmp, sizeof(sgx_dh_msg2_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}

	if (dh_msg3 != NULL) {
		if (memcpy_verw_s(&ms->ms_dh_msg3, sizeof(sgx_dh_msg3_t*), &__tmp, sizeof(sgx_dh_msg3_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dh_msg3 = __tmp;
		memset_verw(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}

	if (memcpy_verw_s(&ms->ms_session_id, sizeof(ms->ms_session_id), &session_id, sizeof(session_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL send_request_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_req_message = req_message_size;
	size_t _len_resp_message = resp_message_size;

	ms_send_request_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_send_request_ocall_t);
	void *__tmp = NULL;

	void *__tmp_resp_message = NULL;

	CHECK_ENCLAVE_POINTER(req_message, _len_req_message);
	CHECK_ENCLAVE_POINTER(resp_message, _len_resp_message);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (req_message != NULL) ? _len_req_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (resp_message != NULL) ? _len_resp_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_send_request_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_send_request_ocall_t));
	ocalloc_size -= sizeof(ms_send_request_ocall_t);

	if (memcpy_verw_s(&ms->ms_src_enclave_id, sizeof(ms->ms_src_enclave_id), &src_enclave_id, sizeof(src_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_dest_enclave_id, sizeof(ms->ms_dest_enclave_id), &dest_enclave_id, sizeof(dest_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (req_message != NULL) {
		if (memcpy_verw_s(&ms->ms_req_message, sizeof(secure_message_t*), &__tmp, sizeof(secure_message_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, req_message, _len_req_message)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_req_message);
		ocalloc_size -= _len_req_message;
	} else {
		ms->ms_req_message = NULL;
	}

	if (memcpy_verw_s(&ms->ms_req_message_size, sizeof(ms->ms_req_message_size), &req_message_size, sizeof(req_message_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_max_payload_size, sizeof(ms->ms_max_payload_size), &max_payload_size, sizeof(max_payload_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (resp_message != NULL) {
		if (memcpy_verw_s(&ms->ms_resp_message, sizeof(secure_message_t*), &__tmp, sizeof(secure_message_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_resp_message = __tmp;
		memset_verw(__tmp_resp_message, 0, _len_resp_message);
		__tmp = (void *)((size_t)__tmp + _len_resp_message);
		ocalloc_size -= _len_resp_message;
	} else {
		ms->ms_resp_message = NULL;
	}

	if (memcpy_verw_s(&ms->ms_resp_message_size, sizeof(ms->ms_resp_message_size), &resp_message_size, sizeof(resp_message_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (resp_message) {
			if (memcpy_s((void*)resp_message, _len_resp_message, __tmp_resp_message, _len_resp_message)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL end_session_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_end_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_end_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_end_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_end_session_ocall_t));
	ocalloc_size -= sizeof(ms_end_session_ocall_t);

	if (memcpy_verw_s(&ms->ms_src_enclave_id, sizeof(ms->ms_src_enclave_id), &src_enclave_id, sizeof(src_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_dest_enclave_id, sizeof(ms->ms_dest_enclave_id), &dest_enclave_id, sizeof(dest_enclave_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

