#include <stdio.h>
#include <string.h>

char s[1000001];

int main() {
    int n, m;
    scanf("%d %d", &n, &m);
    scanf("%s", s);

    int res = 0;
    for (int i = 0; i < m; i++) {
        if (s[i] == 'I') {
            int cnt = 0;

            while (i + 2 < m && s[i + 1] == 'O' && s[i + 2] == 'I') {
                cnt++; i += 2;

                if (cnt >= n) {
                    res++;
                }
            }
        }
    }

    printf("%d\n", res);

    return 0;
}