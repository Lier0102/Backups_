#include <stdio.h>
#include <string.h>

int main() {
    int m;
    scanf("%d", &m);

    int S = 0;
    char op[10]; // toggle/remove xx's len : 0xa
    int x;

    while (m--) {
        scanf("%s", op);

        if (op[0] == 'a' && op[1] == 'd') {
            scanf("%d", &x);
            S |= (1 << x);
        } else if (op[0] == 'r') {
            scanf("%d", &x);
            S &= ~(1 << x);
        } else if (op[0] == 'c') {
            scanf("%d", &x);
            printf("%d\n", (S & (1 << x)) ? 1 : 0);
        } else if (op[0] == 't') {
            scanf("%d", &x);
            S ^= (1 << x);
        } else if (op[0] == 'a' && op[1] == 'l') {
            S = (1 << 21) - 1;
        } else if (op[0] == 'e') {
            S = 0;
        }
    }

    return 0;
}