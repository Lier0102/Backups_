#include <stdio.h>
#include <string.h>

char str[2001];

int main() {
    int t = 1;
    while (1) {
        int left = 0, right = 0;
        scanf("%s", str);
        
        if (str[0] == '-') break;

        int len = strlen(str);

        for (int i = 0; i < len; i++) {
            if (str[i] == '{') {
                left++;
            } else {
                if (left > 0) {
                    left--;
                } else {
                    right++;
                }
            }
        }

        int res = (left + 1) / 2 + (right + 1) / 2;
        printf("%d. %d\n", t++, res);
    }

    return 0;
}