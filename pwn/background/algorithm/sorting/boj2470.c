#include <stdio.h>
#include <stdlib.h>

int a[100001];

int comp(const void *a, const void *b) {
    return (*(int *)a) - (*(int *)b);
}

int main() {
    int n;

    scanf("%d", &n);
    
    for (int i = 0; i < n; i++) scanf("%d", &a[i]);

    qsort(a, n, sizeof(int), comp);

    int left = 0, right = n - 1; // 탐색용
    int l = 0, r = n - 1; // 위치 저장용
    int min = abs(a[left] + a[right]);
    
    while (left < right) {
        int sum = a[left] + a[right];
        int tmp = abs(sum);

        if (tmp < min) {
            min = tmp;
            l = left; r = right;
        }

        if (sum < 0) {
            left++;
        } else {
            right--;
        }
    }

    printf("%d %d\n", a[l], a[r]);

    return 0;
}