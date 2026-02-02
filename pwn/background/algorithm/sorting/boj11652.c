#include <stdio.h>
#include <stdlib.h>

int comp(const void *a, const void *b){
    long long v1 = *(long long *)a;
    long long v2 = *(long long *)b;

    if (v1 < v2) return -1;
    if (v1 > v2) return 1;
    return 0;
}

long long a[100001];

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) scanf("%lld", &a[i]);

    qsort(a, n, sizeof(long long), comp);

    long long ans = a[0];
    int max = 1;
    int cnt = 1;
    for (int i = 1; i < n; i++) {
        if (a[i] == a[i-1]) {
            cnt++;
        } else {
            cnt = 1;
        }

        if (cnt > max) {
            max = cnt;
            ans = a[i];
        }
    }
    
    printf("%lld", ans);

    return 0;
}