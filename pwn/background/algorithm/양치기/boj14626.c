#include <stdio.h>

int main() {
    char isbn[14];
    scanf("%s", isbn);

    int idx = -1;
    for (int i = 0; i < 13; i++) {
        if (isbn[i] == '*') {
            idx = i;
            break;
        }
    }

    for (int i = 0; i <= 9; i++) {
        isbn[idx] = i + '0';

        int sum = 0;
        for (int i = 0; i < 13; i++) {
            int v = isbn[i] - '0';
            if (i % 2 == 0) {
                sum += v * 1;
            } else {
                sum += v * 3;
            }
        }

        if (sum % 10 == 0) {
            printf("%d\n", i);
            break;
        }
    }

    return 0;
}