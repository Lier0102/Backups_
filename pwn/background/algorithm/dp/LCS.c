#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 백트래킹: n^1000이라 불가능
// 아이디어:
// 각자의 가장 큰 부분 수열을 구하고 공통되는 거 찾기
// 

int max(int a, int b){
    return a > b ? a : b;
}

int main() {
    char str1[1001];
    char str2[1001];
    int dp[1001][1001] = {0,}; // 길이
    int len1, len2;

    scanf("%s %s", str1, str2); len1=strlen(str1); len2=strlen(str2);
    // top-down 어떻게 할지 생각하려니까 머리 아파서 쉬운 bottom-up 방식 구현
    for (int i = 1; i <= len1; i++) {
        for (int j = 1; j <= len2; j++) {
            if (str1[i-1] == str2[j-1]) {
                dp[i][j] = dp[i-1][j-1] + 1;
            } else {
                dp[i][j] = max(dp[i-1][j], dp[i][j-1]);
            }
        }
    }

    printf("%d\n", dp[len1][len2]);

    return 0;
}