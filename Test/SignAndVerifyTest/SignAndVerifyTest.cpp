#include "../../include/ECDSA.h"
#include <stdlib.h>
#include <assert.h>

int main() {
    point *BP = createPoint(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    EC *group = createEC(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 
    BP, 0, 7, 1);

    mpz_t privateKey, temp;
    point *publicKey = createPoint(
    "abd9791437093d377ca25ea974ddc099eafa3d97c7250d2ea32af6a1556f92a", 
    "3fe60f6150b6d87ae8d64b78199b13f26977407c801f233288c97ddc4acca326");
    mpz_init_set_str(privateKey, "9f4c9eb899bd86e0e83ecca659602a15b2edb648e2ae4ee4a256b17bb29a1a1e", 16);
    mpz_init_set(temp, privateKey);
    point *test = scalar_multi(temp, group->BasePoint, group);
    assert(mpz_cmp(test->x, publicKey->x) == 0 && mpz_cmp(test->y, publicKey->y) == 0);

    char *message = "Hello!";
    sign *sign = sign_message(privateKey, message, group);
    gmp_printf("Sign: (%Zd, %Zd)\n", sign->r, sign->s);

    if (verifySignature(publicKey, message, sign, group)) printf("PASS!\n");
}