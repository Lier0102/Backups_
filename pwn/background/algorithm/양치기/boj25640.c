#include <stdio.h>
#include <string.h>

int main() {
    char a[5];
    int n, cnt = 0;

    scanf("%s", a);scanf("%d", &n);
    
    for (int i = 0; i < n; i++) {
        char b[5];
        scanf("%s", b);

        if (strcmp(a, b) == 0) {
            cnt++;
        }
    }

    printf("%d\n", cnt);
    
    return 0;
}