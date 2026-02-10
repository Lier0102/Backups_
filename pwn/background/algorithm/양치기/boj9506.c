#include <stdio.h>

void solve(int n) {
    int arr[100001];
    int cnt = 0;
    int sum = 0;

    for (int i = 1; i < n; i++) {
        if (n % i == 0) {
            arr[cnt++] = i;
            sum += i;
        }
    }

    if (sum == n) {
        printf("%d = ", n);
        for (int i = 0; i < cnt; i++) {
            printf("%d", arr[i]);
            if (i < cnt - 1) {
                printf(" + ");
            }
        }
        puts("");
    } else {
        printf("%d is NOT perfect.\n", n);
    }
}

int main() {
    int n;
    while (1) {
        scanf("%d", &n);
        if (n == -1) break;
        solve(n);
    }

    return 0;
}