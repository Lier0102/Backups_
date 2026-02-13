#include <stdio.h>

int main() {
    int t1, t2, t3, t4;
    scanf("%d%d%d%d",&t1,&t2,&t3,&t4);

    int sum = t1 + t2 + t3 + t4;

    printf("%d\n", sum/60);
    printf("%d", sum%60);

    return 0;
}