#include "../../include/ECDSA.h"

int main() {
    point *BP = createPoint("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    EC *group = createEC("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", BP, 0, 7, 1);
    if (is_on_curve(BP, group)) printf("Pass IS On Curve!\n");
    point *negBP = point_neg(BP, group);

    key_pair *kp = make_keypair(group);
    gmp_printf("private->key:%Zd\n", kp->privateKey);
    gmp_printf("publicKey: (%Zd, %Zd)\n", kp->publicKey->x, kp->publicKey->y);
}