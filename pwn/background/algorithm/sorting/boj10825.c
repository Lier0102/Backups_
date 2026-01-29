#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char name[11];
    int kor;
    int eng;
    int mat;
} S;

S stu[100000];

int comp(const void *a, const void *b) {
    S *s1 = (S *)a;
    S *s2 = (S *)b;

    if (s1->kor != s2->kor) {
        return s2->kor - s1->kor;
    }

    if (s1->eng != s2->eng) {
        return s1->eng - s2->eng;
    }

    if (s1->mat != s2->mat) {
        return s2->mat - s1->mat;
    }

    return strcmp(s1->name, s2->name);
}

int main() {
    int n;

    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        scanf("%s %d %d %d", stu[i].name, &stu[i].kor, &stu[i].eng, &stu[i].mat);
    }

    qsort(stu, n, sizeof(S), comp);

    for (int i = 0; i < n; i++) {
        printf("%s\n", stu[i].name);
    }

    return 0;
}