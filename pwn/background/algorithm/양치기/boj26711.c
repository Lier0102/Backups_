#include <stdio.h>
#include <string.h>

char a[5005], b[5005], res[5010];

int main() {
    scanf("%s %s", a, b);

    int len1 = strlen(a);
    int len2 = strlen(b);
    int i = len1 - 1, j = len2 - 1, k = 0;
    int carry = 0;

    while(i >=0 || j >= 0 || carry) {
        int sum = carry;
        if (i >= 0) sum += a[i--] - '0';
        if (j >= 0) sum += b[j--] - '0';

        res[k++] = (sum % 10) + '0';
        carry = sum / 10; // rest part is the carry thingy
    }

    for (int idx = k - 1; idx >= 0; idx--) {
        printf("%c", res[idx]);
    }
    puts("");

    return 0;
}