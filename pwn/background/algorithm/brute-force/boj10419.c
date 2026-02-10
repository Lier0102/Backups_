#include <stdio.h>

// t + s <= d
// t + t^2 <= d

void solve() {
    int d;
    scanf("%d", &d);

    int t = 0;
    while ((t + 1) + (t + 1) * (t + 1) <= d) {
        t++;
    }

    printf("%d\n", t);
}

int main() {
    int t;
    scanf("%d", &t);

    while (t--) {
        solve();
    }

    return 0;
}