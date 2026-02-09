#include <stdio.h>
#include <math.h>

// so HUGE that can't be brute-forced huh
int res; // bss section

void solve(int n, int r, int c) {
    if (n == 0) return; // miss dp challs..

    int half = 1 << (n - 1); // 2 ^ (n - 1);
    int size = half * half;

    if (r < half && c < half) {
        solve(n - 1, r, c);        
    } else if (r < half && c >= half) {
        res += size;
        solve(n - 1, r, c - half);
    } else if (r >= half && c < half) {
        res += size * 2;
        solve(n - 1, r - half, c);
    } else {
        res += size * 3;
        solve(n - 1, r - half, c - half);
    }
}

int main() {
    int n;
    int r, c;
    scanf("%d%d%d", &n, &r, &c);

    solve(n, r, c);
    printf("%d", res);

    return 0;
}