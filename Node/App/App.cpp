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
#include <assert.h>
#include "../../include/ECDSA.h"
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
#define SS_OVER     "ffff1111"
#define SS_BEGIN    "ffffffff"
#define NODE_NUM 8

sgx_enclave_id_t enclave_id = 0;
mpz_t  privateKeySS;
point* publicKey;

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

void str2point(const char *s) {
    char *Sx, *Sy;
    int i, cnt = 0;
    for (i = 0; i < strlen(s); i++) {
        assert(s[i] == ' ' || (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'));
        cnt += (s[i] == ' ');
        assert(cnt < 2);
    }
    for (i = 0; i < strlen(s); i++) {
        if (s[i] == ' ') break;
    }
    Sx = (char *)malloc((i+1)*sizeof(char));
    Sy = (char *)malloc((strlen(s)-i)*sizeof(char));
    for (int j = 0; j < i; j++) {
        Sx[j] = s[j];
    }
    Sx[i] = '\0';
    for (int j = i+1; j < strlen(s); j++) {
        Sy[j-i-1] = s[j];
    }
    Sy[strlen(s)-i-1] = '\0';
    Enclave_createPoint(enclave_id, &publicKey, Sx, Sy);
}

int _tmain(int argc, _TCHAR* argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    if(load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
    }

    // shared memory between Enlave1 and Enclave2 to pass data
    key_t key = ftok("../..", 13*atoi(argv[1]));
    int shmid_msg1 = shmget(key, 32, 0666|IPC_CREAT);
    char *str;
    while (1)
    {
        int flag = 0;
        str = (char*)shmat(shmid_msg1, (void*)0, 0);
        if (strcmp(str, argv[1]) == 0) {
            flag = 1;
        }
        shmdt(str);
        if (flag) break;
    }
    printf("[Node %s] Get sequence: %s\n", argv[1], argv[1]);
    shmctl(shmid_msg1, IPC_RMID, NULL);

    key = ftok("../..", 17*atoi(argv[1]));
    int shmid = shmget(key, 512, 0666 | IPC_CREAT);
    str = (char*)shmat(shmid, (void*)0, 0);

    printf("[TEST IPC %s] Receiving from Enclave1: %s\n", argv[1], str);
    for (int i = 0; i < strlen(str); i++) {
        if (str[i] == ' ') {
            char *s1;
            s1 = (char *)malloc(i+1);
            for (int j = 0; j < i; j++) s1[j] = str[j];
            s1[i] = '\0';
            printf("Get privateKey SS: %s\n", s1);
            str2point(str+i+1);
            mpz_init_set_str(privateKeySS, s1, 16);
            break;
        }
    }
    shmdt(str);
    shmctl(shmid, IPC_RMID, NULL);

    do
    {
        printf("[START %s] Testing create session between Enclave1 (Initiator) and Enclave2 (Responder)\n", argv[1]);
        status = Enclave_test_create_session(enclave_id, &ret_status, enclave_id, 0);
        if (status!=SGX_SUCCESS)
        {
            printf("[END %s] test_create_session Ecall failed: Error code is %x\n", argv[1], status);
            exit(-1);
        }
        else
        {
            if(ret_status==0)
            {
                printf("[END %s] Secure Channel Establishment between Initiator (E1) and Responder (E2) Enclaves successful !!!\n", argv[1]);
            }
            else
            {
                printf("[END %s] Session establishment and key exchange failure between Initiator (E1) and Responder (E2): Error code is %x\n", argv[1], ret_status);
                exit(-1);
            }
        }

        // key_t key = ftok("../..", 10);
        // int shmid = shmget(key, 32, 0666|IPC_CREAT);
        // printf("shmid: %d\n", shmid);
        // while (1)
        // {
        //     char *str = (char*)shmat(shmid, (void*)0, 0);
        //     if (strcmp(SS_OVER, str) == 0) {break; printf("[TEST IPC] Receiving from Enclave1: %s\n", str);}
        // }
        // shmdt(str);
        // shmctl(shmid, IPC_RMID, NULL);

    

#pragma warning (push)
#pragma warning (disable : 4127)
    }while(0);
#pragma warning (pop)

    key = ftok("../..", 13*atoi(argv[1]));
    shmid_msg1 = shmget(key, 32, 0666|IPC_CREAT);
    while (1)
    {
        int flag = 0;
        str = (char*)shmat(shmid_msg1, (void*)0, 0);
        if (atoi(str) == atoi(argv[1])) {
            flag = 1;
        }
        shmdt(str);
        if (flag) break;
    }
    printf("[Node %s] Get sequence: %s\n", argv[1], argv[1]);
    shmctl(shmid_msg1, IPC_RMID, NULL);

    key = ftok("../..", 17*atoi(argv[1]));
    shmid = shmget(key, 512, 0666 | IPC_CREAT);
    str = (char*)shmat(shmid, (void*)0, 0);

    printf("[TEST IPC %s] Receiving from Enclave1: %s\n", argv[1], str);

    mpz_t zeroVal;
    mpz_init_set_str(zeroVal, str, 16);
    mpz_add(privateKeySS, privateKeySS, zeroVal);
    char *S = mpz_get_str(nullptr, 16, privateKeySS);
    printf("Now the privateKeyss = %s\n", S);
    shmdt(str);
    shmctl(shmid, IPC_RMID, NULL);

    do
    {
        printf("[START %s] Testing create session between Enclave1 (Initiator) and Enclave2 (Responder)\n", argv[1]);
        status = Enclave_test_create_session(enclave_id, &ret_status, enclave_id, 0);
        if (status!=SGX_SUCCESS)
        {
            printf("[END %s] test_create_session Ecall failed: Error code is %x\n", argv[1], status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("[END %s] Secure Channel Establishment between Initiator (E1) and Responder (E2) Enclaves successful !!!\n", argv[1]);
            }
            else
            {
                printf("[END %s] Session establishment and key exchange failure between Initiator (E1) and Responder (E2): Error code is %x\n", argv[1], ret_status);
                break;
            }
        }    

#pragma warning (push)
#pragma warning (disable : 4127)
    }while(0);
#pragma warning (pop)

    sgx_destroy_enclave(enclave_id);

    // waitForKeyPress();

    return 0;
}
