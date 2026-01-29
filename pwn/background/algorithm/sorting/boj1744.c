#include <stdio.h>
#include <stdlib.h>

int comp(const void *a, const void *b) {
    return (*(int *)a) - (*(int *)b);
}

// one : 1 * 5 = 5, 1 + 5 = 6, so just add it to res
// neg : they became pos when both of them multiplied
// pos : just mul
// zero : when the count of zeros is odd, should be mul with neg(to remove neg)

int main() {
    int n;
    scanf("%d", &n);

    int pos[51], neg[51]; // +, -
    int idx1=0, idx2=0;
    int one = 0, zero = 0;

    for (int i = 0; i < n; i++) {
        int v;
        scanf("%d", &v);

        if (v > 1) pos[idx1++] = v;
        else if (v == 1) one++;
        else if (v == 0) zero++;
        else neg[idx2++] = v;
    }

    qsort(pos, idx1, sizeof(int), comp);
    qsort(neg, idx2, sizeof(int), comp);

    long long res = 0;

    for (int i = idx1 - 1; i >= 0; i -= 2) {
        if (i - 1 >= 0) res += (pos[i] * pos[i - 1]); // end terms
        else res += pos[i];
    }

    for (int i = 0; i < idx2; i += 2) { // or you can change the end rule to customize this for clause... and I am not looking forward to it.
        if (i + 1 < idx2) res += (neg[i] * neg[i + 1]);
        else {
            if (zero == 0) res += neg[i]; // look above
        }
    }

    res += one;

    printf("%lld\n", res);

    return 0;
}