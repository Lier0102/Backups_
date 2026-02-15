#include <stdio.h>

int main() {
    char a[3];
    double sc = 0.0; // result

    scanf("%s", a);

    if (a[0] == 'F') { puts("0.0"); return 0; }

    if (a[0] == 'A') sc = 4.0;
    else if (a[0] == 'B') sc = 3.0;
    else if (a[0] == 'C') sc = 2.0;
    else if (a[0] == 'D') sc = 1.0;

    if (a[1] == '+') sc += 0.3;
    else if (a[1] == '-') sc -= 0.3;
    // else printf("%lf", sc);

    printf("%.1lf", sc);

    return 0;
}