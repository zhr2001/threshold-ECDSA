#include "../include/ECDSA.h"
#include <assert.h>
#include <stdlib.h>
#include <openssl/sha.h>

point* createPoint(char *x, char *y) {
    point *p = (point*)malloc(sizeof(point));
    mpz_init_set_str(p->x, x, 16);
    mpz_init_set_str(p->y, y, 16);
    return p;
}

EC* createEC(char *p, char *n, point *G, int a, int b, int h) {
    EC *group = (EC*)malloc(sizeof(EC));
    mpz_init_set_str(group->p, p, 16);
    mpz_init_set_str(group->n, n, 16);
    group->BasePoint = G;
    group->a = a;
    group->b = b;
    group->h = h;
    return group;
}

mpz_t* inverse_mod(mpz_t k, mpz_t p) {
    mpz_t *temp = new mpz_t[1], negOne, zero, one;
    mpz_init(*temp);
    mpz_init_set_str(negOne, "-1", 10);
    mpz_init_set_str(zero, "0", 10);
    mpz_init_set_str(one, "1", 10);
    if (mpz_cmp(k, zero) == 0) return nullptr;
    if (mpz_cmp(k, zero) < 0) {
        mpz_set(*temp, k);
        mpz_mul(*temp, *temp, negOne);
        mpz_t *intermidiate = inverse_mod(*temp, p);     
        mpz_sub(*intermidiate, p, *intermidiate);
        mpz_clear(*temp);
        mpz_clear(negOne);
        return intermidiate;
    }

    mpz_t s, olds, t, oldt, r, oldr, quotient, tempS, tempT, tempR;
    mpz_init(quotient); mpz_init(tempR);
    mpz_init(tempS); mpz_init(tempT);
    mpz_init_set_si(s, 0);
    mpz_init_set_si(olds, 1);
    mpz_init_set_si(t, 1);
    mpz_init_set_si(oldt, 0);
    mpz_init_set(r, p);
    mpz_init_set(oldr, k);

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
    mpz_mul(*temp, k, olds);
    mpz_mod(*temp, *temp, p);
    assert(mpz_cmp(*temp, one) == 0);

    mpz_mod(*temp, olds, p);

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

    return temp;
}

int is_on_curve(const point *p, EC *curve) {
    if (p == nullptr) return 1;

    mpz_t x, y, temp1, temp2;
    mpz_init(temp1);
    mpz_init(temp2);
    mpz_init_set(x, p->x);
    mpz_init_set(y, p->y);
    mpz_perfect_power_p(x);
    mpz_pow_ui(temp1, x, 3);
    mpz_pow_ui(temp2, x, curve->a);
    mpz_add(temp1, temp1, temp2);
    mpz_add_ui(temp1, temp1, curve->b);
    mpz_mul(temp2, p->y, p->y);
    mpz_sub(temp1, temp2, temp1);
    mpz_mod(temp1, temp1, curve->p);

    int res = mpz_cmp_ui(temp1, 0);

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(temp1);
    mpz_clear(temp2);

    return res == 0 ? 1 : 0;
}