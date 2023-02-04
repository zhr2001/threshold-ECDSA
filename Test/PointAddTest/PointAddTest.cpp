#include "../../include/ECDSA.h"

int main() {
    point *a = createPoint("11", "a");
    point *b = createPoint("5f", "1f");
    EC *group = createEC("61", 
    "0", a, 2, 3, 1);

    gmp_printf("a+b=(%Zd, %Zd)\n", point_add(a, b, group)->x, point_add(a, b, group)->y);
}