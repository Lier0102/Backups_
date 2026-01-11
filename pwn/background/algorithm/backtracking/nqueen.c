#include <stdio.h>

int N;
int count; // bss
int col[101];

void backtrack(int);
int is_safe(int, int);

int main() {
    count = 0;
    scanf("%d", &N); backtrack(0);

    printf("%d\n", count);

    return 0;
}

void backtrack(int row) {
    if (row == N) {
        count++;
        return;
    }

    for (int i = 0; i < N; i++) {
        if (is_safe(row, i)) {
            col[row] = i;
            backtrack(row+1);
        }
    }
}

int is_safe(int row, int c) {
    for (int i = 0; i < row; i++) {
        if (col[i] == c) return 0;

        if (abs(col[i] - c) == abs(i - row)) return 0;
    }

    return 1;
}