#ifndef _SECRET_SHARING_H_
#define _SECRET_SHARING_H_

#include <gmp.h>

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

RandomPoly* createPoly(mpz_t k0, int t, mpz_t range);

mpz_t* getPolyValue(const RandomPolynomial *f, int x, mpz_t modeP);

SS* createSS(int threshold, int n, mpz_t secret, mpz_t modeP);

mpz_t* combiner(const DecryptoInfo *secrets, mpz_t modeP);

#ifdef __cplusplus
}
#endif

#endif