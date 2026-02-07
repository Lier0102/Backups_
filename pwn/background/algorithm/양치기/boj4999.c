#include <stdio.h>
#include <string.h>

int main() {
    char a[1001];
    char b[1001];

    scanf("%s", a);
    scanf("%s", b);

    if (strlen(a) >= strlen(b)) puts("go");
    else puts("no");

    return 0;
}