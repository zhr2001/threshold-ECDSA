#include "../../include/ECDSA.h"

int main() {
    mpz_t k, p, correctRes;
    mpz_init_set_str(k, "7", 10);
    mpz_init_set_str(p, "11", 10);
    gmp_printf("k= %Zd\n",k);
    gmp_printf("p= %Zd\n",p);
    mpz_t *res = inverse_mod(k, p);
    mpz_init_set_str(correctRes, "8", 10);
    gmp_printf("correct= %Zd\n",correctRes);
    gmp_printf("res= %Zd\n",*res);
}