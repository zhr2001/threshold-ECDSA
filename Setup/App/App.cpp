#include <stdio.h>
#include <map>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "../../include/SecretSharing.h"
#include "../Enclave/Enclave_u.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <ctime>

#define NODE_NUM    11
#define THRESH      5
#define MODE_P "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain main

SS* createSecretSharings() {
    mpz_t randomNumber2Secret, p;
    mpz_init(randomNumber2Secret);
    mpz_init_set_str(p, MODE_P, 16);
    gmp_randstate_t state;
    unsigned long seed = time(NULL);
	gmp_randinit_default(state);
	gmp_randseed_ui(state, seed);
    while (mpz_cmp_si(randomNumber2Secret, 0) <= 0 || mpz_cmp(randomNumber2Secret, p) >= 0)
    {
        mpz_urandomb(randomNumber2Secret, state, 256);
    }
    return createSS(THRESH, NODE_NUM, randomNumber2Secret, p);
}

extern std::map<sgx_enclave_id_t, uint32_t> g_enclave_id_map;

sgx_enclave_id_t enclave_id;

#define ENCLAVE_SETUP_NAME "libenclavesetup.signed.so"

void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key...\n");
    temp = scanf_s("%c", &ch);
}

uint32_t load_enclaves()
{
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    ret = sgx_create_enclave(ENCLAVE_SETUP_NAME, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    return SGX_SUCCESS;
}

int _tmain(int argc, TCHAR* argv[]) {
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if (load_enclaves() != SGX_SUCCESS) {
        printf("\nLoad Enclave Failure\n");
    }

    SS *ss = createSecretSharings();
    int i = 0;

    do 
    {
        key_t key = ftok("../..", i+1);
        int shmid = shmget(key, 1024, 0666|IPC_CREAT);
        char *str = (char*)shmat(shmid, (void*)0, 0);
        printf("[TEST IPC] Sending to Node Enclave: Secret Sharing from Enclave1\n");
        str = mpz_get_str(nullptr, 16, ss->keyPartitions[i]);
        shmdt(str);
        printf("[START] Testing create session between SetUp Enclave and Node Enclave\n");
        status = Enclave_test_create_session(enclave_id, &ret_status, enclave_id, 0);
        status = SGX_SUCCESS;
        if (status != SGX_SUCCESS) 
        {
            printf("[END] test_create_session Ecall failed: Error code is %x\n", status);
        } else 
        {
            if (ret_status == 0)
            {
               printf("[END] Session establishment and key exchange failure between SetUp and Node: Error code is %x\n", ret_status);
            } 
            else 
            {
                printf("[END] Session establishment and key exchange failure between Initiator (E1) and Responder (E2): Error code is %x\n", ret_status);
                break;
            }
        }
        i++;
    } while (i < ss->n); // TODO: Add while condition
    

    sgx_destroy_enclave(enclave_id);

    waitForKeyPress();

    return 0;
}