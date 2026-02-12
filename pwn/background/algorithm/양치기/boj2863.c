#include <stdio.h>

int main() {
    double a, b, c, d;
    scanf("%lf %lf %lf %lf", &a, &b, &c, &d);
    double res[4];

    res[0] = (a/c) + (b/d);
    res[1] = (c/d) + (a/b);
    res[2] = (d/b) + (c/a);
    res[3] = (b/a) + (d/c);

    double max = res[0];
    int ans = 0;

    for (int i = 1; i < 4; i++) {
        if (res[i] > max) {
            max = res[i];
            ans = i;
        }
    }

    printf("%d\n", ans);
}