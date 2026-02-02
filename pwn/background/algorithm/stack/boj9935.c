#include <stdio.h>
#include <string.h>

int main() {
    char str[1000001];
    char bomb[37]; // bomb strss
    char res[1000001];
    int len, len2;
    int top = 0;

    scanf("%s", str);
    scanf("%s", bomb);

    len = strlen(str);
    len2 = strlen(bomb);

    for (int i = 0; i < len; i++) {
        res[top++] = str[i];

        if (top >= len2) {
            if (res[top - 1] == bomb[len2 - 1]) {
                int flag = 1; // it might be a bomb
                for (int j = 0; j < len2; j++) {
                    if (res[top - 1 - j] != bomb[len2 - 1 - j]) {
                        flag = 0;
                        break;
                    }
                }

                // if (!flag) {

                // }
                if (flag) {
                    top -= len2; // boom!
                }
            }
        }
    }

    if (top == 0) {
        puts("FRULA");
    } else {
        res[top] = '\0'; // end of res, because of for (int i = 0; i < len; ...) {...}
        printf("%s", res);
    }

    return 0;
}