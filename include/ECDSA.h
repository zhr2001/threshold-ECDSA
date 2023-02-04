#ifndef _ECDSA_H_
#define _ECDSA_H_

#include "gmp.h"

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

point* createPoint(char *x, char *y);

point* duplicatePoint(const point *p);

void freePoint(point *append);

EC* createEC(char *p, char *n, point *G, int a, int b, int h);

mpz_t* inverse_mod(const mpz_t k, const mpz_t p);

int is_on_curve(const point *p, const EC *curve);

point* point_neg(const point *p, const EC *curve);

point* point_add(const point *a, const point *b, const EC *curve);

point* scalar_multi(mpz_t k, const point *a, const EC *curve);

key_pair* make_keypair(const EC *curve);

mpz_t* hash_message(const char *message, int length);

sign* sign_message(mpz_t privateKey, const char *message, const EC *curve);

int verifySignature(mpz_t publicKey, const char *message, const sign *signature, const EC *curve);

#ifdef __cplusplus
}
#endif

#endif