#ifndef _ECDSA_H_
#define _ECDSA_H_

#include "gmp.h"

typedef struct point {
    mpz_t x;
    mpz_t y;
} point;

typedef struct keyPair {
    mpz_t publicKey;
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
    point BasePoint; 
} EC;

#ifdef __cplusplus
extern "C" {
#endif

mpz_t* inverse_mod(mpz_t k, mpz_t p);

int is_on_clave(const point *p, EC *curve);

point point_neg(const point *p, EC *curve);

point point_add(const point *a, const point *b, EC *curve);

point scalar_multi(mpz_t k, const point *a, EC *curve);

key_pair make_keypair(EC *curve);

mpz_t* hash_message(char *message, int length);

sign sign_message(mpz_t privateKey, char *message, EC *curve);

int verifySignature(mpz_t publicKey, char *message, sign signature, EC *curve);

#ifdef __cplusplus
}
#endif

#endif