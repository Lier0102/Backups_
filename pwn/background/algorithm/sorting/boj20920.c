#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char word[11];
    int cnt;
    int len;
} words;

words w[100001];
words w2[100001];

int comp(const void *a, const void *b) {
    return strcmp(((words *)a)->word, ((words *)b)->word);
}

int comp2(const void *a, const void *b) {
    words *w1 = (words *)a;
    words *w2 = (words *)b;

    if (w1->cnt != w2->cnt) return w2->cnt - w1->cnt;
    if (w1->len != w2->len) return w2->len - w1->len;

    return strcmp(w1->word, w2->word);
}

int main() {
    int n, m;
    scanf("%d %d", &n, &m);

    int idx = 0;
    for (int i = 0; i < n; i++) {
        char tmp[11];
        scanf("%s", tmp);

        int len = strlen(tmp);

        if (len >= m) {
            strcpy(w[idx].word, tmp);
            w[idx].len = len;
            idx++;
        }
    }

    qsort(w, idx, sizeof(words), comp); // sort inside

    int idx2 = 0;

    for (int i = 0; i < idx; i++) {
        if (i > 0 && strcmp(w[i].word, w[i - 1].word) == 0) {
            w2[idx2 - 1].cnt++;
        } else {
            strcpy(w2[idx2].word, w[i].word);
            w2[idx2].len = w[i].len;
            w2[idx2].cnt = 1;
            idx2++;
        }
    }

    qsort(w2, idx2, sizeof(words), comp2);

    for (int i = 0; i < idx2; i++) {
        printf("%s\n", w2[i].word);
    } 

    return 0;
}