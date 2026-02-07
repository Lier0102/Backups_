#include <stdio.h>

int main() {
    int n;
    char *a = "Hello World, Judge ";

    scanf("%d", &n);

    for (int i = 1; i <= n; i++) {
        printf("%s%d!\n", a, i);
    }
}