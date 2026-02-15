#include <stdio.h>

int deque[51];
int size;

int find(int target) {
    for (int i = 0; i < size; i++) {
        if (deque[i] == target) return i;
    }
}

int main() {
    int n, m;
    scanf("%d %d", &n, &m);

    size = n;
    for (int i = 0; i < n; i++) deque[i] = i + 1;

    int res = 0;
    for (int i = 0; i < m; i++) {
        int v;
        scanf("%d", &v);

        int idx = find(v);

        int left = idx;
        int right = size - idx;

        if (left <= right) {
            res += left;

            for (int j = 0; j < left; j++) {
                int tmp = deque[0];
                for (int k = 0; k < size - 1; k++) deque[k] = deque[k + 1];
                deque[size - 1] = tmp;
            }
        } else {
            res += right;
            
            for (int j = 0; j < right; j++) {
                int tmp = deque[size - 1];
                for (int k = size - 1; k >= 0; k--) deque[k] = deque[k - 1];
                deque[0] = tmp;
            }
        }

        for (int j = 0; j < size - 1; j++) deque[j] = deque[j + 1];
        size--;
    }

    printf("%d", res);

    return 0;
}