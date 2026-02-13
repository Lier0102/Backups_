#include <stdio.h>

int main() {
    int sc;
    int sum = 0;

    for (int i = 0; i < 5; i++) {
        scanf("%d", &sc);

        if (sc < 40) {
            sc = 40;
        }

        sum += sc;
    }

    printf("%d", sum / 5);

    return 0;
}