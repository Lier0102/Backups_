#include <stdio.h>

int main() {
    int sum, tmp;

    scanf("%d", &sum);

    for (int i = 0; i < 9; i++) {
        scanf("%d", &tmp);
        sum -= tmp;
    }

    printf("%d\n", sum);

    return 0;
}