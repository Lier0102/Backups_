#include <stdio.h>
#include <string.h>

typedef struct {
    char type[21];
    int cnt;
} category; // Category

int main() {
    int t;
    scanf("%d", &t);

    while (t--) {
        int n;
        scanf("%d", &n);

        category c[31];
        int size = 0; // for the category size

        for (int i = 0; i < n; i++) {
            char name[21], type[21];
            scanf("%s %s", name, type);

            int flag = 0;

            for (int j = 0; j < size; j++) {
                if (strcmp(c[j].type, type) == 0) {
                    c[j].cnt++;
                    flag = 1;
                    break;
                }
            }

            if (!flag) {
                strcpy(c[size].type, type);
                c[size].cnt = 1;
                size++;
            }
        }

        long long res = 1;
        for (int i = 0; i < size; i++) {
            res *= (c[i].cnt + 1);
        }
        
        printf("%lld\n", res-1);
    }

    return 0;
}