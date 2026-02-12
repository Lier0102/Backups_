#include <stdio.h>

int main() {
    int l,a,b,c,d;
    scanf("%d%d%d%d%d",&l,&a,&b,&c,&d);

    int kor = (a+c-1)/c;

    int mat = (b+d-1)/d;

    int res = l - ((kor > mat) ? kor : mat);
    if (res < 0) res = 0;
    printf("%d", res);

    return 0;
}