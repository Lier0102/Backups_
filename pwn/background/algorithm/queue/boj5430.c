#include <stdio.h>
#include <string.h>

int deque[100001];

// [], < len(2)
//  ',', len=(100,000)
// num = 1, 2, 3, max len=(3 * 100,000)
// ...

void solve() {
    char p[100001];
    int n;
    char arr[400005];

    scanf("%s", p);
    scanf("%d", &n);
    scanf("%s", arr);

    int front = 0, rear = 0;
    char *ptr = strtok(arr, "[],");

    while (ptr != NULL) {
        deque[rear++] = atoi(ptr);
        ptr = strtok(NULL, "[],");
    }

    int flag = 0; // reversed or not
    int eflag = 0; // flag for error

    for (int i = 0; p[i] != '\0'; i++) {
        if (p[i] == 'R') {
            flag = !flag;
        } else if (p[i] == 'D') {
            if (front >= rear) {
                eflag = 1;
                break;
            }
            if (flag) rear--;
            else front++;
        }
    }

    if (eflag) puts("error");
    else {
        printf("[");
        if (flag) {
            for (int i = rear - 1; i >= front; i--) {
                printf("%d%s", deque[i], (i == front ? "" : ","));
            }
        } else {
            for (int i = front; i < rear; i++) {
                printf("%d%s", deque[i], (i == rear - 1 ? "" : ","));
            }
        }
        puts("]");
    }
}

int main() {
    int t;
    scanf("%d", &t);

    while (t--) solve(); // { ... } << lot. a lot.

    return 0;
}