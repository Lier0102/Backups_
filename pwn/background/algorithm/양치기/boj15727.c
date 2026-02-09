#include <stdio.h>

int main() {
    int l;
    scanf("%d", &l);

    if (l % 5 == 0) {
        printf("%d\n", l / 5);
    } else {
        printf("%d\n", (l / 5) + 1);
    }

    // or just...
    // (l + 4) / 5 maybe?

    return 0;
}