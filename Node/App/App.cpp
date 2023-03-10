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


// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "../Enclave/Enclave_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

sgx_enclave_id_t enclave_id = 0;

#define ENCLAVE_PATH "libenclavenode.so"

void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key....\n");
    temp = scanf_s("%c", &ch);
}

uint32_t load_enclaves()
{
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    return SGX_SUCCESS;
}

int _tmain(int argc, _TCHAR* argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if(load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
    }

    // shared memory between Enlave1 and Enclave2 to pass data
    key_t key = ftok("../..", 1);
    int shmid = shmget(key, 1024, 0666 | IPC_CREAT);
    char *str = (char*)shmat(shmid, (void*)0, 0);

    printf("[TEST IPC] Receiving from Enclave1: %s\n", str);

    shmdt(str);
    shmctl(shmid, IPC_RMID, NULL);

    do
    {
        printf("[START] Testing create session between Enclave1 (Initiator) and Enclave2 (Responder)\n");
        status = Enclave_test_create_session(enclave_id, &ret_status, enclave_id, 0);
        if (status!=SGX_SUCCESS)
        {
            printf("[END] test_create_session Ecall failed: Error code is %x\n", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("[END] Secure Channel Establishment between Initiator (E1) and Responder (E2) Enclaves successful !!!\n");
            }
            else
            {
                printf("[END] Session establishment and key exchange failure between Initiator (E1) and Responder (E2): Error code is %x\n", ret_status);
                break;
            }
        }

#pragma warning (push)
#pragma warning (disable : 4127)
    }while(0);
#pragma warning (pop)

    sgx_destroy_enclave(enclave_id);

    waitForKeyPress();

    return 0;
}
