#include "ECDSA.h"
#include <assert.h>
#include <openssl/sha.h>

mpz_t* inverse_mod(mpz_t k, mpz_t p) {
    if (k == 0) return nullptr;

    mpz_t temp, negOne, zero, one;
    mpz_init_set_str(negOne, "-1", 10);
    mpz_init_set_str(zero, "0", 10);
    mpz_init_set_str(one, "1", 10);
    if (k < 0) {
        mpz_set(temp, k);
        mpz_mul(temp, temp, negOne);
        mpz_t *intermidiate = inverse_mod(temp, p);     
        mpz_sub(*intermidiate, p, *intermidiate);
        mpz_clear(temp);
        mpz_clear(negOne);
        return intermidiate;
    }

    mpz_t s, olds, t, oldt, r, oldr, quotient, tempS, tempT, tempR;
    mpz_set(s, zero);
    mpz_set(olds, one);
    mpz_set(t, olds);
    mpz_set(oldt, s);
    mpz_set(r, k);
    mpz_set(oldr, p);

    while (mpz_cmp(r, zero) > 0)
    {
        mpz_div(quotient, oldr, r);
        mpz_mul(tempR, quotient, r);
        mpz_sub(tempR, oldr, tempR);
        mpz_mul(tempS, quotient, s);
        mpz_sub(tempS, olds, tempS);
        mpz_mul(tempT, quotient, t);
        mpz_sub(tempT, oldt, tempT);
        mpz_set(oldr, r);
        mpz_set(olds, s);
        mpz_set(oldt, t);
        mpz_set(r, tempR);
        mpz_set(s, tempS);
        mpz_set(t, tempT);
    }

    assert(mpz_cmp(oldr, one) == 0);
    mpz_mul(temp, k, olds);
    mpz_mod(temp, temp, p);
    assert(mpz_cmp(temp, one) == 0);

    mpz_mod(temp, olds, p);

    mpz_clear(zero);
    mpz_clear(one);
    mpz_clear(negOne);
    mpz_clear(s);
    mpz_clear(t);
    mpz_clear(r);
    mpz_clear(oldt);
    mpz_clear(olds);
    mpz_clear(oldr);
    mpz_clear(tempR);
    mpz_clear(tempS);
    mpz_clear(tempT);
    mpz_clear(quotient);

    return &temp;
}