#include <stdio.h>
#include <string.h>

// stack -> stack
// res -> res
// temp -> tmp

// 1. Check if it is valid
// 2. 

int main() {
    char str[31];
    char stack[31];

    scanf("%s", str);

    int top = -1;
    int res = 0;
    int tmp = 1;
    int len = strlen(str);
    int flag = 1; // true/false

    for (int i = 0; i < len; i++) {
        if (str[i] == '(') {
            tmp *= 2;
            stack[++top] = '(';
        } else if (str[i] == '[') {
            tmp *= 3;
            stack[++top] = '[';
        } else if (str[i] == ')') {
            if (top == -1 || stack[top] != '(') {
                flag = 0;
                break;
            }
            if (str[i - 1] == '(') {
                res += tmp;
            }

            top--;
            tmp /= 2;
        } else if (str[i] == ']') {
            if (top == -1 || stack[top] != '[') {
                flag = 0;
                break;
            }

            if (str[i-1] == '[') {
                res += tmp;
            }

            top--;
            tmp /= 3;
        }
    }

    if (!flag || top != -1) {
        printf("0");
    } else{
        printf("%d\n", res);
    }
}