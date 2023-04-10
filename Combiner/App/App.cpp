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
#define SS_OVER         "ffff1111"
#define SS_BEGIN        "ffffffff"
#define MESSAGE  "begin"
#define NODE_NUM 8
#define DEBUG 1

extern std::map<sgx_enclave_id_t, uint32_t> g_enclave_id_map;

sgx_enclave_id_t enclave_id;

pthread_mutex_t mutex;

#define ENCLAVE_SETUP_NAME "libenclavesetup.so"

typedef struct thread_para {
    int i;
    SS *ss;
} t_para;

typedef struct thread_sign {
    int i;
    SS *k,*c;
    char *r, *e;
} s_para;

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

int cnt = 0;

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
    char *iii = itoa(i);
    strncpy(str, iii,strlen(iii));
    free(iii);
    printf("[SetUp %d] Get sequence: %s\n", i, itoa(i));
    shmdt(str);

    key = ftok("../..", 17*i);
    int shmid_msg3 = shmget(key, 512, 0666|IPC_CREAT);
    printf("[TEST IPC] Sending to Node Enclave: Secret Sharing from Enclave1\n");
    char *c_str = (char*)shmat(shmid_msg3, (void*)0, 0);
    char *S = mpz_get_str(nullptr, 16, ss->keyPartitions[i-1]);
    strncpy(c_str, S, strlen(S));
    printf("%d Secret sharing: %s\n", i, c_str);
    shmdt(c_str);

    if (DEBUG) goto sleep;
    printf("[START] Testing create session between SetUp Enclave and Node Enclave\n");
    status = Enclave_test_create_session(enclave_id, &ret_status, enclave_id, 0);
    status = SGX_SUCCESS;
    if (status != SGX_SUCCESS) 
    {
        printf("[END %d] test_create_session Ecall failed: Error code is %x\n", i, status);
    } else 
    {
        if (ret_status == 0)
        {
            printf("[END %d] Secure Channel Establishment between Setup and Node successful !!!\n", i);
        } 
        else 
        {
            printf("[END %d] Session establishment and key exchange failure between SetUp and Node: Error code is %x\n", i, ret_status);
        }
    }

sleep:
    sleep(1);
    shmctl(shmid_msg1, IPC_RMID, NULL);
    shmctl(shmid_msg3, IPC_RMID, NULL);
    cnt += 1;
    pthread_mutex_unlock(&mutex);
    return nullptr;
}

void* sign_thread_function(void *args) {
    // brodcast r, e, k, c
    s_para *s = (s_para*)args;
    int i = s->i;
    sgx_status_t status;
    uint32_t ret_status;

    pthread_mutex_lock(&mutex);
    printf("into sign \n");

    key_t key = ftok("../..", 13*i);
    int shmid_msg1 = shmget(key, 32, 0666|IPC_CREAT);
    char *str = (char*)shmat(shmid_msg1, (void*)0, 0);
    strncpy(str, itoa(i),strlen(itoa(i)));
    printf("[SetUp %d] Get sequence: %s\n", i, itoa(i));
    shmdt(str);

    key = ftok("../..", 17*i);
    int shmid_msg3 = shmget(key, 1024, 0666|IPC_CREAT);
    printf("[TEST IPC] Sending to Node Enclave: Secret Sharing from Enclave1\n");
    char *t = (char*)shmat(shmid_msg3, (void*)0, 0);
    char *c_str = t;
    char *S = mpz_get_str(nullptr, 16, s->k->keyPartitions[i-1]);
    strncpy(t, S, strlen(S));
    t[strlen(S)] = ' ';
    t = t+strlen(S)+1;

    strncpy(t, s->e, strlen(s->e));
    t[strlen(s->e)] = ' ';
    t = t+strlen(s->e)+1;

    strncpy(t, s->r, strlen(s->r));
    t[strlen(s->r)] = ' ';
    t = t+strlen(s->r)+1;

    S = mpz_get_str(nullptr, 16, s->c->keyPartitions[i-1]);
    strncpy(t, S, strlen(S));

    printf("%d Secret sharing: %s\n", i, c_str);
    shmdt(c_str);

    sleep(1);
    key = ftok("../..", 19*i);
    int shmid = shmget(key, 512, 0666 | IPC_CREAT);
    str = (char*)shmat(shmid, (void*)0, 0);

    printf("[TEST IPC## %d] Receiving sign part from Node: %s\n", i, str);
    shmdt(str);

    shmctl(shmid_msg1, IPC_RMID, NULL);
    shmctl(shmid_msg3, IPC_RMID, NULL);
    shmctl(shmid, IPC_RMID, NULL);
    pthread_mutex_unlock(&mutex);
    return nullptr;
}

int _tmain(int argc, TCHAR* argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    if (load_enclaves() != SGX_SUCCESS) {
        printf("\nLoad Enclave Failure\n");
    }

    key_t key = ftok("../..", 10);
    int shmid = shmget(key, 32, 0666|IPC_CREAT);
    while (1)
    {
        int flag = 0;
        char *str = (char*)shmat(shmid, (void*)0, 0);
        if (strcmp(SS_OVER, str) == 0) {
            flag = 1;
        }
        shmdt(str);
        if (flag) {
            printf("[TEST IPC] Receiving from Enclave1: %s\n", SS_OVER);
            break;
        }
    }
    shmctl(shmid, IPC_RMID, NULL);    

    Enclave_init(enclave_id);

    pthread_t tidp[NODE_NUM];
    t_para p[NODE_NUM];
    pthread_mutex_init(&mutex,NULL); 

    SS *ss;
    Enclave_createZeroSecretSharings(enclave_id, &ss, 1);

    for (int i = 0; i < NODE_NUM; i++) {
        p[i].i = i+1;
        p[i].ss = ss;
        int ret = pthread_create(&tidp[i], NULL, thread_function, (void*)&p[i]);  
        if(ret!=0)  
        {  
            printf("Create %d failed\n",i);  
            exit(ret);  
        }  
    }

    for (int i=0;i  < NODE_NUM;i++)
    {
        pthread_join(tidp[i], NULL);  //problem in this line
    }

    while (cnt < NODE_NUM);

    mpz_t* u;
    mpz_t* A;
    point* beta;

    SS* k, *a;
    Enclave_createRandomSecretSharings(enclave_id, &k, 1);
    Enclave_createRandomSecretSharings(enclave_id, &a, 1);
    SS* b, *c;
    Enclave_createZeroSecretSharings(enclave_id, &b, 2);
    Enclave_createZeroSecretSharings(enclave_id, &c, 2);

    SS* kaplusb = (SS*)malloc(sizeof(SS));
    kaplusb->keyPartitions = (mpz_t*)malloc(k->n*sizeof(mpz_t));
    kaplusb->n = k->n;
    for (int i = 0; i < k->n; i++) {
        mpz_t t;
        mpz_init_set(t, k->keyPartitions[i]);
        mpz_mul(t,t,a->keyPartitions[i]);
        mpz_add(t,t,b->keyPartitions[i]);
        mpz_init_set(kaplusb->keyPartitions[i], t);
        mpz_clear(t);
    }
    if (SGX_SUCCESS == Enclave_DecryptoSS(enclave_id, &u, kaplusb, 2)) {
        printf("SB!\n");
    }
    Enclave_DecryptoGA(enclave_id, &beta, A);
    printf("SB!\n");
    point *R;
    Enclave_getRxy(enclave_id, &R, u, beta);
    printf("SB!\n");
    mpz_t r;
    mpz_init_set(r, R->x);
    printf("SB!\n");
    Enclave_mod(enclave_id, &r);
    printf("SB!\n");
    s_para s[NODE_NUM];
    mpz_t *e;
    Enclave_hash(enclave_id, &e, MESSAGE, strlen(MESSAGE));
    printf("SB!\n");
    char *e_res = mpz_get_str(nullptr, 16, *e);
    printf("hash info : %s \n", e_res);
    char *r_res = mpz_get_str(nullptr, 16, r);

    for (int i = 0; i < NODE_NUM; i++) {
        s[i].i = i+1;
        s[i].c = c;
        s[i].k = k;
        s[i].e = e_res;
        s[i].r = r_res;
        
        int ret = pthread_create(&tidp[i], NULL, sign_thread_function, (void*)&s[i]);  
        if(ret!=0)  
        {  
            printf("Create %d failed\n",i);  
            exit(ret);  
        }  
    }

    for (int i=0;i  < NODE_NUM;i++)
    {
        pthread_join(tidp[i], NULL);  //problem in this line
    }

    sgx_destroy_enclave(enclave_id);

    return 0;
}