#include <stdio.h>
#include <string.h>

char parrot[101][101][33];
int front[101], rear[101];
char l[500001];

int main() {
    int n;
    if (scanf("%d", &n) != 1) return 0;
    
    while (getchar() != '\n');

    for (int i = 0; i < n; i++) {
        char v[10001];
        if (!fgets(v, sizeof(v), stdin)) continue;
        
        v[strcspn(v, "\n")] = 0;

        char *ptr = strtok(v, " ");
        while (ptr != NULL) {
            strcpy(parrot[i][rear[i]++], ptr);
            ptr = strtok(NULL, " ");
        }
    }

    if (!fgets(l, sizeof(l), stdin)) return 0;
    l[strcspn(l, "\n")] = 0;

    char *ptr = strtok(l, " ");
    int flag = 1;

    while (ptr != NULL) {
        int found = 0;
        for (int i = 0; i < n; i++) {
            if (front[i] < rear[i] && strcmp(parrot[i][front[i]], ptr) == 0) {
                front[i]++;
                found = 1;
                break;
            }
        }

        if (!found) {
            flag = 0;
            break;
        }
        ptr = strtok(NULL, " ");
    }

    for (int i = 0; i < n; i++) {
        if (front[i] < rear[i]) {
            flag = 0;
            break;
        }
    }

    if (flag) printf("Possible\n");
    else printf("Impossible\n");

    return 0;
}