#include <stdio.h>

// 개인적으로 nqueen이랑 약간 비슷한 느낌을 받음
// 휴리스틱으로 하려고 했으나, 백트래킹 배우는 도중에
// 하기에는 내 지능이 부족해 2차원 배열로 구현

// 전역변수 여러개 쓰려니까 뭔가 코드가 맘에 안 들어서..

// bss
int board[9][9];

// 빈 곳 찾기
int is_empty(int *row, int *col) {
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            if (board[i][j] == 0) {
                *row = i;
                *col = j;
                return 1;
            }
        }
    }
    return 0;
}

// 이 쪽은 위치에 변화 주는 느낌(=empty)가 아니라 포인터 안 씀
int is_check(int row, int col, int n) {
    for (int i = 0; i < 9; i++)
        if (board[row][i] == n) return 0;

    for (int i = 0; i < 9; i++)
        if (board[i][col] == n) return 0;

    int start1 = (row/3)*3;
    int start2 = (col/3)*3;

    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            if (board[start1 + i][start2 + j] == n)
                return 0;
        }
    }

    return 1;
}

int solve() {
    int row, col;

    if (!is_empty(&row, &col)) {
        return 1;
    }

    for (int i = 1; i <= 9; i++) {
        if (is_check(row, col, i)) {
            board[row][col] = i;

            if (solve()) return 1;

            board[row][col] = 0;
        }
    }
    return 0;
}

int main() {
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            scanf("%d", &board[i][j]);
        }
    }

    solve();

    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            printf("%d ", board[i][j]);
        }
        puts("");
    }

    return 0;
}