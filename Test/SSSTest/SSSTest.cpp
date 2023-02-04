#include "../../include/SecretSharing.h"

int main() {
    mpz_t secret, p;
    mpz_init_set_str(secret, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    mpz_init_set_str(p,      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    SS *ss = createSS(3, 11, secret, p);
    int sub[5] = {2,4,5,6,7};
    mpz_t part[5];
    mpz_init_set(part[0], ss->keyPartitions[1]);
    mpz_init_set(part[1], ss->keyPartitions[3]);
    mpz_init_set(part[2], ss->keyPartitions[4]);
    mpz_init_set(part[3], ss->keyPartitions[5]);
    mpz_init_set(part[4], ss->keyPartitions[6]);
    DecryptoInfo d = {sub, 3, part};
    mpz_t *decrypted = combiner(&d, p);
    gmp_printf("Secret: %Zd\n", *decrypted);
}