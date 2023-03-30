#ifndef _ECDSA_H_
#define _ECDSA_H_

#include "sgx_tgmp.h"

typedef struct point {
    mpz_t x;
    mpz_t y;
} point;

typedef struct keyPair {
    point *publicKey;
    mpz_t privateKey;
} key_pair;

typedef struct signature {
    mpz_t r;
    mpz_t s;
} sign;

/* p -- the field number
 * n -- a prime order of a subgroup
 * (a, b) -- y^2 = x^3+ax+b
 * BasePoint -- the generator of EC Group
 * */
typedef struct EllipticCurve {
    mpz_t p, n;
    int a;
    int b;
    int h;
    point* BasePoint; 
} EC;

#ifdef __cplusplus
extern "C" {
#endif

sign* sign_message(mpz_t* privateKey, const char *message, const EC *curve);

int verifySignature(const point *publicKey, const char *message, const sign *signature, const EC *curve);

#ifdef __cplusplus
}
#endif

#endif