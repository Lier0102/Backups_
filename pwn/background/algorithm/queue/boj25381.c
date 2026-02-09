#include <stdio.h>
#include <string.h>

char s[300005];
int qA[300005], qB[300005];
int fA, rA, fB, rB;

int main() {
    scanf("%s", s);
    int len = strlen(s);
    int res = 0;

    for (int i = 0; i < len; i++) {
        if (s[i] == 'A') {
            qA[rA++] = i;
        } else if (s[i] == 'B') {
            qB[rB++] = i;
        } else if (s[i] == 'C') {
            if (fB < rB) {
                fB++;
                res++;
            }
        }
    }
    
    while (fA < rA && fB < rB) {
        if (qA[fA] < qB[fB]) {
            fA++;
            fB++;
            res++;
        } else {
            fB++;
        }
    }

    printf("%d\n", res);
    return 0;
}