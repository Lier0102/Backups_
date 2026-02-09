#include <stdio.h>
#include <string.h>

// 'A' * 25 < 25
// contains null-byte, so max-len should be 26.

typedef struct {
    char word[25][26];
    int top;
} stk;

void init(stk *s) {
    s->top = -1;
}

int empty(stk *s) {
    return s->top == -1;
}

void push(stk *s, char *v) {
    s->top++;
    strcpy(s->word[s->top], v);
}

char *pop(stk *s) {
    if (empty(s)) {
        return NULL;
    }
    return s->word[s->top--];
}

int main() {
    int n;
    scanf("%d", &n);
    getchar();

    for (int i = 1; i <= n; i++) {
        char a[100];
        fgets(a, sizeof(a), stdin);

        a[strcspn(a, "\n")] = '\0';

        stk s;
        init(&s);

        char *word = strtok(a, " ");
        while (word != NULL) {
            push(&s, word);
            word = strtok(NULL, " ");
        }

        printf("Case #%d:", i);

        while (!empty(&s)) {
            printf(" %s", pop(&s));
        }
        puts("");
    }

    return 0;
}