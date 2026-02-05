#include <stdio.h>

// 1
// 1 100 1  << done

// else do



typedef struct {
    int score;
    int time;
} Stack;

Stack stk[1000001];
int top = -1;

int main() {
    int n;
    long long res = 0;

    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        int min;
        scanf("%d", &min);

        if (min == 1) {
            int a, t;
            scanf("%d %d", &a, &t);

            if (t - 1 == 0) {
                res += a;
            } else {
                top++;
                //stk[top++].score = a;
                stk[top].score = a;
                stk[top].time = t - 1;
            }
        } else {
            if (top != -1) {
                stk[top].time--;

                if (stk[top].time == 0) {
                    res += stk[top].score;
                    top--;
                }
            }
        }
    }

    printf("%lld", res);

    return 0;
}