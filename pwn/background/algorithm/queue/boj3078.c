#include <stdio.h>
#include <string.h>

int queue[21][300001];
int front[21], rear[21];

int main() {
    int n, k;
    scanf("%d %d", &n, &k);

    long long res = 0;

    for (int i = 0; i < n; i++) {
        char v[21];
        scanf("%s", v);

        int len = strlen(v);

        while (front[len] < rear[len] && i - queue[len][front[len]] > k) {
            front[len]++;
        }

        res += (rear[len] - front[len]);

        queue[len][rear[len]++] = i;
    }

    printf("%lld\n", res);

    return 0;
}