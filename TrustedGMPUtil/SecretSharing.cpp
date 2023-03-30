#include "../include/SecretSharing.h"
#include <stdlib.h>
#include <sgx_trts.h>
#include <ctime>

RandomPoly* createPoly(mpz_t k0, int t, mpz_t range) {
    RandomPoly *rp = (RandomPoly*)malloc(sizeof(RandomPoly));
    rp->k = (mpz_t *)malloc((t-1)*sizeof(mpz_t));
    rp->t = t;
    mpz_init_set(rp->k0, k0);

    gmp_randstate_t state;
    uint32_t val;
    sgx_read_rand((unsigned char *) &val, 4);
	gmp_randinit_default(state);
	gmp_randseed_ui(state, val);

    for (int i = 0; i < t-1; i++) {
        mpz_init_set_si(rp->k[i], -1);
        while (mpz_cmp_si(rp->k[i], 0) < 0 || mpz_cmp(rp->k[i], range) > 0)
        {
            mpz_urandomb(rp->k[i], state, 256);
        }
    }

    return rp;
}

mpz_t* getPolyValue(const RandomPolynomial *f, int x, mpz_t modeP) {
    mpz_t *temp = new mpz_t[1];
    mpz_init_set_si(temp[0], 0);

    /* QinJiushao's algorithm
     * */
    for (int i = 0; i < f->t-1; i++) {
        mpz_mul_si(temp[0], temp[0], x);
        mpz_add(temp[0], temp[0], f->k[f->t-2-i]);
        mpz_mod(temp[0], temp[0], modeP);
    }
    mpz_mul_si(temp[0], temp[0], x);
    mpz_add(temp[0], temp[0], f->k0);
    mpz_mod(temp[0], temp[0], modeP);

    return temp;
}

SS* createSS(int threshold, int n, mpz_t secret, mpz_t modeP) {
    RandomPoly *rb = createPoly(secret, threshold, modeP);
    SS* ss = (SS*)malloc(sizeof(SS));
    ss->keyPartitions = (mpz_t *)malloc(n * sizeof(mpz_t));
    ss->n = n;
    for (int i = 0; i < n; i++) {
        mpz_init_set(ss->keyPartitions[i], *getPolyValue(rb, i+1, modeP));
    }
    return ss;
}

mpz_t* getLagrangeOpVal(int *sub, int t, int j, mpz_t fj, mpz_t modeP) {
    int sum = 1, diviend = 1;
    for (int i = 0; i < t; i++) {
        if (i+1 != j)  {
            sum *= -1*sub[i];
            diviend *= sub[j-1]-sub[i];
        }
    }


    mpz_t* temp = new mpz_t[1], temp2;
    mpz_init(temp[0]);
    mpz_mul_si(temp[0], fj, sum);
    mpz_mod(temp[0], temp[0], modeP);
    mpz_init_set_si(temp2, diviend);
    mpz_invert(temp2, temp2, modeP);
    mpz_mul(temp[0], temp[0], temp2);
    mpz_mod(temp[0], temp[0], modeP);

    mpz_clear(temp2);

    return temp;
}

mpz_t* combiner(const DecryptoInfo *secrets, mpz_t modeP) {
    mpz_t *secret = new mpz_t[1];
    mpz_init(*secret);
    for (int i = 0; i < secrets->t; i++) {
        mpz_add(secret[0], secret[0], *getLagrangeOpVal(
            secrets->sub, secrets->t, i+1, secrets->keyPartitions[i], modeP
        ));
    }
    mpz_mod(secret[0], secret[0], modeP);
    return secret;
}

SS* createSS(int threshold, int n, mpz_t *secret, mpz_t *modeP) {
    return createSS(threshold, n, *secret, *modeP);
}

mpz_t* combiner(const DecryptoInfo *secrets, mpz_t* modeP) {
    return combiner(secrets, *modeP);
}
