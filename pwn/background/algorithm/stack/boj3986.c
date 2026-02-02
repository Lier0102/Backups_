#include <stdio.h>
#include <string.h>

char str[100001];
char stack[100001];

int main() {
    int n;
    int cnt = 0;
    scanf("%d", &n);

    while (n--) {
        int len;
        scanf("%s", str);

        len = strlen(str);

        if ((len % 2)) continue; // assert if len % 2 equals zero

        int top = -1;
        for (int i = 0; i < len; i++) {
            if (top != -1 && stack[top] == str[i]) {
                top--;
            } else {
                stack[++top] = str[i];
            }
        }

        if (top == -1) {
            cnt++;
        }
    }

    printf("%d\n", cnt);

    return 0;
}