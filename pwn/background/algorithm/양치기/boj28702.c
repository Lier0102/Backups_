#include <stdio.h>
#include <ctype.h>

int main() {
    char s[3][9];
    int v = 0;

    for (int i = 0; i < 3; i++) {
        scanf("%s", s[i]);

        if (isdigit(s[i][0])) {
            int n = atoi(s[i]);
            v = n + (3 - i);
        }
    }

    if (v % 3 == 0 && v % 5 == 0) {
        puts("FizzBuzz");
    } else if (v % 3 == 0) {
        puts("Fizz");
    } else if (v % 5 == 0) {
        puts("Buzz");
    } else {
        printf("%d\n", v);
    }

    return 0;
}