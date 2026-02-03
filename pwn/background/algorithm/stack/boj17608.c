#include <stdio.h>
#include <stdlib.h>

int a[100001];

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) scanf("%d", &a[i]);

    int cnt = 1; // (2 ≤ N ≤ 100,000)
    int max = a[n-1]; // not front, but rear;

    for (int i = n - 2; i >= 0; i--) {
        if (a[i] > max) {
            max = a[i];
            cnt++;
        }
    }

    printf("%d\n", cnt);

    return 0;
}