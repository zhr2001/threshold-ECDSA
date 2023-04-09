#include "../include/ECDSA.h"
#include <string.h>
#include <assert.h>
#include "sgx_trts.h"
#include "openssl/sha.h"
#include "openssl/crypto.h"

char numberToHex(int m) {
    assert(0<=m && m<= 15);
    if (m >= 0 && m <= 9) return m+'0';
    else return m-10+'a';
}

char* convertHash(const unsigned char* md, int len) {
    char *ret = (char *)malloc(2*len*sizeof(char));
    int i = 0;
    for (i = 0; i < len; i++) {
        ret[2*i] = numberToHex(md[i] / 16);
        ret[2*i+1] = numberToHex(md[i] % 16);
    }
    ret[2*len] = '\0';
    return ret;
}

point* createPoint(char *x, char *y) {
    point *p = (point*)malloc(sizeof(point));
    mpz_init_set_str(p->x, x, 16);
    mpz_init_set_str(p->y, y, 16);
    return p;
}

point* duplicatePoint(const point *p) {
    point *res = (point*)malloc(sizeof(point));
    mpz_init_set(res->x, p->x);
    mpz_init_set(res->y, p->y);
    return res;
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

void freePoint(point *append) {
    assert(append != nullptr);
    mpz_clear(append->x);
    mpz_clear(append->y);
    free(append);
}

mpz_t* inverse_mod(const mpz_t k, const mpz_t p) {
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

mpz_t* inverse_mod(const mpz_t *k, const mpz_t *p) {
    return inverse_mod(*k, *p);
}


int is_on_curve(const point *p, const EC *curve) {
    assert(curve != nullptr);
    if (p == nullptr) return 1;

    mpz_t x, y, temp1, temp2;
    mpz_init(temp1);
    mpz_init(temp2);
    mpz_init_set(x, p->x);
    mpz_init_set(y, p->y);
    mpz_pow_ui(temp1, x, 3);
    mpz_mul_ui(temp2, x, curve->a);
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

point* point_neg(const point *p, const EC *curve) {
    assert(is_on_curve(p, curve));

    if (p == nullptr) return nullptr;

    point* res = (point*)malloc(sizeof(point));
    mpz_init_set(res->x, p->x);
    mpz_init(res->y);
    mpz_mul_si(res->y, p->y, -1);
    mpz_mod(res->y, res->y, curve->p);

    assert(is_on_curve(res, curve));

    return res;
}

point* point_add(const point *a, const point *b, const EC *curve) {
    assert(is_on_curve(a, curve));
    assert(is_on_curve(b, curve));

    if (a == nullptr) return duplicatePoint(b);
    if (b == nullptr) return duplicatePoint(a);
    
    if (mpz_cmp(a->x, b->x) == 0 && mpz_cmp(a->y, b->y) != 0) {
        return nullptr;
    }

    mpz_t m,x3,y3;
    mpz_init(m);
    mpz_init(x3);
    mpz_init(y3);

    if (mpz_cmp(a->x, b->x) == 0) {
        mpz_mul(m, a->x, a->x);
        mpz_mul_si(m, m, 3);
        mpz_add_ui(m, m, curve->a);
        mpz_mul_si(x3, a->y, 2);
        mpz_set(x3, *(inverse_mod(x3, curve->p)));
        mpz_mul(m, m, x3);
    } else {
        mpz_sub(m, a->x, b->x);
        mpz_set(m, *(inverse_mod(m, curve->p)));
        mpz_sub(x3, a->y, b->y);
        mpz_mul(m, m, x3);
    }

    mpz_mul(x3, m, m);
    mpz_sub(x3, x3, a->x);
    mpz_sub(x3, x3, b->x);
    mpz_sub(y3, x3, a->x);
    mpz_mul(y3, y3, m);
    mpz_add(y3, y3, a->y);
    mpz_mul_si(y3, y3, -1);

    mpz_mod(x3, x3, curve->p);
    mpz_mod(y3, y3, curve->p);

    point *res = (point*)malloc(sizeof(point));
    mpz_init_set(res->x, x3);
    mpz_init_set(res->y, y3);

    mpz_clear(x3);
    mpz_clear(y3);
    mpz_clear(m);

    assert(is_on_curve(res, curve));

    return res;
}

point* scalar_multi(mpz_t k, const point *p, const EC *curve) {
    assert(is_on_curve(p, curve));

    mpz_t temp;
    mpz_init(temp);
    mpz_mod(temp, k, curve->n);
    if (mpz_cmp_si(temp, 0) == 0 && p == nullptr) return nullptr;

    if (mpz_cmp_si(k, 0) < 0) {
        mpz_mul_si(temp, k, -1);
        return scalar_multi(temp, point_neg(p, curve), curve);
    }
    
    mpz_set(temp, k);

    point *res = nullptr;
    point *append = duplicatePoint(p);

    while (mpz_cmp_si(temp, 0) > 0)
    {
        if (mpz_odd_p(temp)) {
            res = point_add(res, append, curve);
        }

        append = point_add(append, append, curve);

        mpz_div_ui(temp, temp, 2);
    }

    mpz_clear(temp);

    assert(is_on_curve(res, curve));
    
    return res;
}

point* scalar_multi(mpz_t* k, const point *p, const EC *curve) {
    return scalar_multi(*k, p, curve);
}

key_pair* make_keypair(const EC *curve) {
    mpz_t privateKey;
    point *publicKey = (point *)malloc(sizeof(point));
    mpz_init(privateKey);
    mpz_init(publicKey->x);
    mpz_init(publicKey->y);

    gmp_randstate_t state;
    uint32_t val; 
    sgx_read_rand((unsigned char *) &val, 4);
	gmp_randinit_default(state);
	gmp_randseed_ui(state, val);
    
    while (mpz_cmp_si(privateKey, 0) <= 0 || mpz_cmp(privateKey, curve->n) >= 0)
    {
        mpz_urandomb(privateKey, state, 256);
    }

    publicKey = scalar_multi(privateKey, curve->BasePoint, curve);

    key_pair *kp = (key_pair *)malloc(sizeof(key_pair));
    mpz_init_set(kp->privateKey, privateKey);
    kp->publicKey = publicKey;
    mpz_clear(privateKey);
    return kp;
}

mpz_t* hash_message(const char *message, int length, const EC *curve) {
    unsigned char md[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)message, length, md);
    mpz_t *res = new mpz_t[1], temp;
    mpz_init(temp);
    mpz_init_set_str(res[0], convertHash(md, SHA512_DIGEST_LENGTH), 16);
    int len = mpz_sizeinbase(curve->n, 2);
    int reslen = mpz_sizeinbase(res[0], 2);
    if (reslen > len){
        mpz_set_ui(temp, 2);
        mpz_pow_ui(temp, temp, reslen-len);
        mpz_div(res[0], res[0], temp);
    }

    mpz_clear(temp);

    assert(mpz_sizeinbase(res[0], 2) <= mpz_sizeinbase(curve->n, 2));
    return res;
}

sign* sign_message(mpz_t privateKey, const char *message, const EC *curve) {
    mpz_t *hash_info = hash_message(message, strlen(message), curve);

    sign *res = (sign*)malloc(sizeof(sign));
    mpz_init(res->r);
    mpz_init(res->s);

    mpz_t k;
    mpz_init(k);

    gmp_randstate_t state;
    uint32_t val;
    sgx_read_rand((unsigned char *) &val, 4);
	gmp_randinit_default(state);
	gmp_randseed_ui(state, val);

    while (mpz_cmp_si(res->r, 0) == 0 || mpz_cmp_si(res->s, 0) == 0)
    {
        while (mpz_cmp_si(k, 0) <= 0 || mpz_cmp(k, curve->n) >= 0)
        {
            mpz_urandomb(k, state, 256);
        }
        point *p = scalar_multi(k, curve->BasePoint, curve);
        mpz_mod(res->r, p->x, curve->n);
        mpz_mul(res->s, res->r, privateKey);
        mpz_add(res->s, *hash_info, res->s);
        mpz_mul(res->s, *(inverse_mod(k, curve->n)), res->s);
        mpz_mod(res->s, res->s, curve->n);
    }
    
    mpz_clear(k);

    return res;
}

int verifySignature(const point *publicKey, const char *message, const sign *signature, const EC *curve) {
    mpz_t *hash_info = hash_message(message, strlen(message), curve);
    mpz_t *w = inverse_mod(signature->s, curve->n);
    
    mpz_t temp1, temp2;
    mpz_init(temp1);
    mpz_init(temp2);

    mpz_mul(temp1, *hash_info, *w);
    mpz_mod(temp1, temp1, curve->n);
    mpz_mul(temp2, signature->r, *w);
    mpz_mod(temp2, temp2, curve->n);
    point *res = point_add(scalar_multi(temp1, curve->BasePoint, curve), scalar_multi(temp2, publicKey, curve), curve);

    mpz_mod(temp1, signature->r, curve->n);
    mpz_mod(temp2, res->x, curve->n);

    if (mpz_cmp(temp1, temp2) == 0) {
        mpz_clear(temp1);
        mpz_clear(temp2);
        return 1;
    } else {
        mpz_clear(temp1);
        mpz_clear(temp2);
        return 0;
    }
}

sign* sign_message(mpz_t* privateKey, const char *message, const EC *curve) {
    return sign_message(*privateKey, message, curve);
}