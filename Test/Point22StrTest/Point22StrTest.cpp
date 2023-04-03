#include "../../include/ECDSA.h"
#include <string.h>
#include "gmp.h"
#include "assert.h"

char* point2str(const point *p) {
    char *Sx = mpz_get_str(nullptr, 16, p->x);
    char *Sy = mpz_get_str(nullptr, 16, p->y);
    char *res = nullptr;
    strcat(res, Sx);
    strcat(res, ",");
    strcat(res, Sy);
    return res;
}

point* str2point(const char *s) {
    char *Sx, *Sy;
    int i, cnt = 0;
    for (i = 0; i < strlen(s); i++) {
        assert(s[i] == ',' || (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'));
        cnt += (s[i] == ',');
        assert(cnt < 2);
    }
    for (i = 0; i < strlen(s); i++) {
        if (s[i] == ',') break;
    }
    Sx = (char *)malloc((i+1)*sizeof(char));
    Sy = (char *)malloc((strlen(s)-i)*sizeof(char));
    for (int j = 0; j < i; j++) {
        Sx[j] = s[j];
    }
    Sx[i] = '\0';
    for (int j = i+1; j < strlen(s); j++) {
        Sy[j-i-1] = s[j];
    }
    Sy[strlen(s)-i-1] = '\0';
    return createPoint(Sx, Sy);
}

int main() {
    point *BP = createPoint("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    EC *group = createEC("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", BP, 0, 7, 1);
    printf("(%s)\n", point2str(BP));
    char *s = point2str(BP);
    point *res = str2point(s);
    if (mpz_cmp(res->x, BP->x) == 0 && mpz_cmp(res->y, BP->y) == 0) {
        printf("Passed!\n");
    } else printf("NoPass!\n");
}