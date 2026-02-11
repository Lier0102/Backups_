#include <stdio.h>
#include <stdlib.h>

int main() {
    int arr[11];
    int cur = 0;
    int max = 0;

    for (int i = 0; i < 10; i++) {
        scanf("%d", &arr[i]);
    }

    for (int i = 0; i < 10; i++) {
        cur += arr[i];

        int diff_c = abs(100 - cur); // diff for the current
        int diff_b = abs(100 - max);// diff for the best
    
        if (diff_c < diff_b) {
            max = cur;
        } else if (diff_c == diff_b) {
            if (cur > max) {
                max = cur;
            }
        }
    }

    printf("%d", max);
}