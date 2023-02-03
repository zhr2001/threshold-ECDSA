#include "../../include/ECDSA.h"

int main() {
    mpz_t k, p, correctRes;
    mpz_init_set_str(k, "3", 10);
    mpz_init_set_str(p, "5", 10);
    mpz_t *res = inverse_mod(k, p);
    mpz_init_set_str(correctRes, "2", 10);
    gmp_printf("res= %Zd\n",*res);
}