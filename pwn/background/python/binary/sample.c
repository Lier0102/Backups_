#include <stdio.h>

typedef struct { // mind that there're also padding bytes vro.
    double v;
    int t;
    char c;
} test;

int main() {
    test t = {6.7f, 6, 'A'};
    FILE *fp = fopen("output", "w"); // since it's for testing, just write on it.
    fwrite(&t, sizeof(test), 1, fp);
    fclose(fp);

    return 0;
}