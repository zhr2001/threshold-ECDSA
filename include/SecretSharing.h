#ifndef _SECRET_SHARING_H_
#define _SECRET_SHARING_H_

#include "sgx_tgmp.h"

typedef struct SecreatShares {
    int n;
    mpz_t *keyPartitions;
} SS;

typedef struct DecryptoInfomation {
    int *sub, t;
    mpz_t *keyPartitions;
} DecryptoInfo;

typedef struct RandomPolynomial {
    int t;
    mpz_t *k, k0;
} RandomPoly;

#ifdef __cplusplus
extern "C" {
#endif

SS* createSS(int threshold, int n, mpz_t* secret, mpz_t* modeP);

mpz_t* combiner(const DecryptoInfo *secrets, mpz_t* modeP);

#ifdef __cplusplus
}
#endif

#endif