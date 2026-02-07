#include <stdio.h>

typedef struct {
    int idx, prior; // priority
} Doc;

int main() {
    int t;
    scanf("%d", &t);

    while (t--) {
        int n, m;

        scanf("%d %d", &n, &m);

        Doc queue[10001];
        int cnt[10] = {0};

        for (int i = 0; i < n; i++) {
            queue[i].idx = i;
            scanf("%d", &queue[i].prior);

            cnt[queue[i].prior]++;
        }

        int front = 0, rear = n;
        int res = 0;

        while (1) {
            Doc cur = queue[front]; // initials
            int flag = 0; // same as above

            for (int i = 9; i > cur.prior; i--) { // 1 <= importance <= 9
                if (cnt[i] > 0) {
                    flag = 1;
                    break;
                }
            }

            if (flag) {
                queue[rear] = cur; // q[front];
                rear++;
                front++;
            } else {
                res++;
                cnt[cur.prior]--;
                front++;

                if (cur.idx == m) {
                    printf("%d\n", res);
                    break;
                }
            }
        }
    }

    return 0;
}