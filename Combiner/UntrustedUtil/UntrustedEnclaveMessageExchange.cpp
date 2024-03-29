/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "sgx_eid.h"
#include "error_codes.h"
#include "datatypes.h"
#include "sgx_urts.h"
#include "UntrustedEnclaveMessageExchange.h"
#include "sgx_dh.h"
#include <map>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

//Makes an sgx_ecall to the destination enclave to get session id and message1
ATTESTATION_STATUS session_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;

    // wait for Enclave2 to fill msg1
    printf("[OCALL IPC] Waiting for Enclave2 to generate SessionID and message1...\n");
    sleep(5);

    printf("[OCALL IPC] SessionID and message1 should be ready\n");

    // for session id
    printf("[OCALL IPC] Retriving SessionID from shared memory\n");
    key_t key_session_id = ftok("../..", 3);
    int shmid_session_id = shmget(key_session_id, sizeof(uint32_t), 0666|IPC_CREAT); //Create shared memory
    uint32_t* tmp_session_id = (uint32_t*)shmat(shmid_session_id, (void*)0, 0); // Connect shared memory
    memcpy(session_id, tmp_session_id, sizeof(uint32_t));
    shmdt(tmp_session_id); // Discrete the memory

    // for msg1
    printf("[OCALL IPC] Retriving message1 from shared memory\n");
    key_t key_msg1 = ftok("../..", 2);
    int shmid_msg1 = shmget(key_msg1, sizeof(sgx_dh_msg1_t), 0666|IPC_CREAT);
    sgx_dh_msg1_t *tmp_msg1 = (sgx_dh_msg1_t*)shmat(shmid_msg1, (void*)0, 0);
    memcpy(dh_msg1, tmp_msg1, sizeof(sgx_dh_msg1_t));
    shmdt(tmp_msg1);

    ret = SGX_SUCCESS;

	if (ret == SGX_SUCCESS)
		return SUCCESS;
	else
	    return INVALID_SESSION;

}
//Makes an sgx_ecall to the destination enclave sends message2 from the source enclave and gets message 3 from the destination enclave
ATTESTATION_STATUS exchange_report_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;

    // for msg2 (filled by Enclave1)
    printf("[OCALL IPC] Passing message2 to shared memory for Enclave2\n");
    key_t key_msg2 = ftok("../..", 4);
    int shmid_msg2 = shmget(key_msg2, sizeof(sgx_dh_msg2_t), 0666|IPC_CREAT);
    sgx_dh_msg2_t *tmp_msg2 = (sgx_dh_msg2_t*)shmat(shmid_msg2, (void*)0, 0);
    memcpy(tmp_msg2, dh_msg2, sizeof(sgx_dh_msg2_t));
    shmdt(tmp_msg2);

    // wait for Enclave2 to process msg2
    printf("[OCALL IPC] Waiting for Enclave2 to process message2 and generate message3...\n");
    sleep(5);

    // retrieve msg3 (filled by Enclave2)
    printf("[OCALL IPC] Message3 should be ready\n");
    printf("[OCALL IPC] Retrieving message3 from shared memory\n");
    key_t key_msg3 = ftok("../..", 5);
    int shmid_msg3 = shmget(key_msg3, sizeof(sgx_dh_msg3_t), 0666|IPC_CREAT);
    sgx_dh_msg3_t *tmp_msg3 = (sgx_dh_msg3_t*)shmat(shmid_msg3, (void*)0, 0);
    memcpy(dh_msg3, tmp_msg3, sizeof(sgx_dh_msg3_t));
    shmdt(tmp_msg3);

    ret = SGX_SUCCESS;
	if (ret == SGX_SUCCESS)
		return SUCCESS;
	else
	    return INVALID_SESSION;

}

//Make an sgx_ecall to the destination enclave function that generates the actual response
ATTESTATION_STATUS send_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id,secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
	uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;

	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}

	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave_generate_response(dest_enclave_id, &status, src_enclave_id, req_message, req_message_size, max_payload_size, resp_message, resp_message_size);
			break;
		case 2:
			ret = Enclave_generate_response(dest_enclave_id, &status, src_enclave_id, req_message, req_message_size, max_payload_size, resp_message, resp_message_size);
			break;
		case 3:
			ret = Enclave_generate_response(dest_enclave_id, &status, src_enclave_id, req_message, req_message_size, max_payload_size, resp_message, resp_message_size);
			break;
	}
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else
	    return INVALID_SESSION;

}

//Make an sgx_ecall to the destination enclave to close the session
ATTESTATION_STATUS end_session_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;

	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}

	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave_end_session(dest_enclave_id, &status, src_enclave_id);
			break;
		case 2:
			ret = Enclave_end_session(dest_enclave_id, &status, src_enclave_id);
			break;
		case 3:
			ret = Enclave_end_session(dest_enclave_id, &status, src_enclave_id);
			break;
	}
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else
	    return INVALID_SESSION;

}

void ocall_print_string(const char *str)
{
    printf("[SetUp] %s", str);
}
