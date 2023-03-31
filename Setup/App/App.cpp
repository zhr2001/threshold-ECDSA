#include <stdio.h>
#include <map>
#include <stdlib.h>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "../../include/SecretSharing.h"
#include "../Enclave/Enclave_u.h"
#include "pthread.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <ctime>

#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain main
#define SS_OVER     "ffff1111"
#define SS_BEGIN    "ffffffff"
#define NODE_NUM 11

extern std::map<sgx_enclave_id_t, uint32_t> g_enclave_id_map;

sgx_enclave_id_t enclave_id;

pthread_mutex_t mutex;

#define ENCLAVE_SETUP_NAME "libenclavesetup.so"

typedef struct thread_para {
    int i;
    SS *ss;
} t_para;

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

char* itoa(int i) {
    int len = 0;
    while (10 * len <= i)
    {
        len = len+1;
    }
    char *res = (char *)malloc((len+1) * sizeof(char));
    for (int j = len-1; j >= 0; j --) {
        res[j] = i%10+'0';
        i = i/10;
    }
    res[len] = '\0';
    return res;
}

void* thread_function(void* args) {
    t_para *p = (t_para *)args;
    int i = p->i;
    SS *ss = p->ss; 
    sgx_status_t status;
    uint32_t ret_status;

    pthread_mutex_lock(&mutex);

    key_t key = ftok("../..", 13*i);
    int shmid_msg1 = shmget(key, 32, 0666|IPC_CREAT);
    char *str = (char*)shmat(shmid_msg1, (void*)0, 0);
    strncpy(str, itoa(i),strlen(itoa(i)));
    printf("[SetUp] Get sequence: %s\n", itoa(i));
    shmdt(str);

    key = ftok("../..", 17*i);
    int shmid_msg3 = shmget(key, 32, 0666|IPC_CREAT);
    printf("[TEST IPC] Sending to Node Enclave: Secret Sharing from Enclave1\n");
    char *c_str = (char*)shmat(shmid_msg3, (void*)0, 0);
    char *S = mpz_get_str(nullptr, 16, ss->keyPartitions[i-1]);
    strncpy(c_str, S, strlen(S));
    printf("Secret sharing: %s\n", c_str);
    shmdt(c_str);

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
            printf("[END] Secure Channel Establishment between Setup and Node successful !!!\n");
        } 
        else 
        {
            printf("[END] Session establishment and key exchange failure between SetUp and Node: Error code is %x\n", ret_status);
            exit(-1);
        }
    }
    shmctl(shmid_msg1, IPC_RMID, NULL);
    shmctl(shmid_msg3, IPC_RMID, NULL);

    pthread_mutex_unlock(&mutex);
    return nullptr;
}

int _tmain(int argc, TCHAR* argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    if (load_enclaves() != SGX_SUCCESS) {
        printf("\nLoad Enclave Failure\n");
    }

    pthread_t tidp[NODE_NUM];
    pthread_mutex_init(&mutex,NULL); 

    SS *ss;
    Enclave_createSecretSharings(enclave_id, &ss);

    for (int i = 0; i < NODE_NUM; i++) {
        t_para p;
        p.i = i+1;
        p.ss = ss;
        int ret = pthread_create(&tidp[i],NULL, thread_function, (void*)&p);  
        if(ret!=0)  
        {  
            printf("Create %d failed\n",i);  
            exit(ret);  
        }  
    }

    for (int i=0;i<NODE_NUM;i++)
    {
        pthread_join(tidp[i],NULL);  //problem in this line
    }
    
    key_t key = ftok("../..", 10);
    int shmid = shmget(key, 32, 0666|IPC_CREAT);
    printf("shmid: %d\n", shmid);
    char *str = (char*)shmat(shmid, (void*)0, 0);
    printf("[TEST IPC] Sending to Node Enclave: SecretSharing over\n");
    strncpy(str, SS_OVER, strlen(SS_OVER));
    shmdt(str);

    sgx_destroy_enclave(enclave_id);

    waitForKeyPress();

    return 0;
}