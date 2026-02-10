#include <stdio.h>

void solve() {
    int tmp;
    scanf("%d", &tmp);

    int q = tmp / 25; tmp %= 25;// quater(25 cents)
    int d = tmp / 10; tmp %= 10;// dime(10 cents)
    int n = tmp / 5; tmp %= 5;// nickel(5 cents)
    int p = tmp; // just a cent

    printf("%d %d %d %d\n", q, d, n, p);
}

int main() {
    int t;
    scanf("%d", &t);

    while (t--) {
        solve();
    }

    return 0;
}