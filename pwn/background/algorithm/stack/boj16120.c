#include <stdio.h>
#include <string.h>

char stk[1000001];
char str[1000001];
int top = -1;

void push(char v) {
    stk[++top] = v;
}

int main() {
    scanf("%s", str);

    int len = strlen(str);

    for (int i = 0; i < len; i++) {
        push(str[i]);

        if (top >= 3) {
            if (stk[top-3] == 'P' &&
                stk[top-2] == 'P' &&
                stk[top-1] == 'A' &&
                stk[top] == 'P') {
                    top -= 3;
            }
        }
    }

    if (top == 0 && stk[0] == 'P') {
        puts("PPAP");
    } else {
        puts("NP");
    }

    return 0;
}