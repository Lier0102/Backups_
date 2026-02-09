#include <stdio.h>

char origin[100005];
char norigin[100005]; // humurous

int main() {
    int n, cnt = 0;

    scanf("%d", &n);

    scanf("%s", origin); scanf("%s", norigin);

    for (int i = 0; i < n; i++) {
        if (origin[i] == norigin[i]) {
            cnt++;
        }
    }

    printf("%d\n", cnt);
}