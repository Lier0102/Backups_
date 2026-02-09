#include <stdio.h>

char msg[1000005];

int main() {
    scanf("%s", msg);

    for (int i = 0; msg[i] != '\0'; i++) {
        msg[i] = msg[i] - 32;
    }

    printf("%s\n", msg);

    return 0;
}