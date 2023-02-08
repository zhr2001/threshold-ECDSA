#include "../../include/ECDSA.h"

int main() {
    point *a = createPoint("11", "a");
    point *b = createPoint("5f", "1f");
    EC *group = createEC("61", 
    "0", a, 2, 3, 1);

    gmp_printf("a+b=(%Zd, %Zd)\n", point_add(a, b, group)->x, point_add(a, b, group)->y);

    point *c = createPoint("3", "6");
    EC *G = createEC("61", 
    "5", c, 2, 3, 20);
    mpz_t temp;
    mpz_init_set_str(temp, "2", 10);
    point *res = scalar_multi(temp, c, G);
    point *check = point_add(c, c, G);
    gmp_printf("2c=(%Zd, %Zd)\n", res->x, res->y);
    gmp_printf("c+c=(%Zd, %Zd)\n", check->x, check->y);
}