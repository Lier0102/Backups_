#include <stdio.h>

int fruit[200001];
int s[10]; // sort of these fruits

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        scanf("%d", &fruit[i]);
    }

    int left = 0, right = 0;
    int max = 0;
    int types = 0; // 

    while (right < n) {
        if (s[fruit[right]] == 0) {
            types++;
        }
        s[fruit[right]]++;

        while (types > 2) {
            s[fruit[left]]--;
            if (s[fruit[left]] == 0) {
                types--;
            }
            left++;
        }

        int cur_len = right - left + 1;
        if (cur_len > max) {
            max = cur_len;
        }

        right++;
    }

    printf("%d", max);

    return 0;
}