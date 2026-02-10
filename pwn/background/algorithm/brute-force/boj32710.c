#include <stdio.h>

int main() {
    int n;
    int flag = 0;
    scanf("%d", &n);

    for (int i = 2; i <= 9; i++) {
        for (int j = 1; j <= 9; j++) {
            int res = i * j;

            if (n == i || n == j || n == res) {
                flag = 1;
                break;
            }
        }
        if (flag) break;
    }

    printf("%d", flag);
}