#include <stdio.h>

int map[128][128]; // maximum = 128
int wh = 0;
int bl = 0; // white/blue cnt

void solve(int x, int y, int size) {
    int c = map[x][y]; // current color
    int flag = 1;

    for (int i = x; i < x + size; i++) {
        for (int j = y; j < y + size; j++) {
            if (map[i][j] != c) {
                flag = 0;
                break;
            }
        }
        
        if (!flag) break; // optimized
    }

    if (flag) {
        if (c == 0) wh++;
        else bl++;
        return;
    }

    int next_size = size / 2;

    solve(x, y, next_size);
    solve(x, y + next_size, next_size);
    solve(x + next_size, y, next_size);
    solve(x + next_size, y + next_size, next_size);
}

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            scanf("%d", &map[i][j]);
        }
    }

    solve(0, 0, n);

    printf("%d\n%d\n", wh, bl);
    
    return 0;
}