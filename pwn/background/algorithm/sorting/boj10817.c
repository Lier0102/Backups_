// #include <stdio.h>
// #include <stdlib.h>

// int comp(const void *a, const void *b) {
//     return (*(int *)a - *(int *)b);
// }

// int main(void) {
//     int a[3];
    
//     for (int i = 0; i < 3; i++) scanf("%d", &a[i]);

//     qsort(a, 3, sizeof(int), comp);

//     printf("%d\n", a[1]);

//     return 0;
// }

// #include <stdio.h>

// int main() {
//     int a[3];

//     for (int i = 0; i < 3; i++) scanf("%d", &a[i]);

//     for (int i = 1; i < 3; i++) {
//         int v = a[i];
//         int j = i - 1;

//         while (j >= 0 && a[j] >= v) {
//             a[j + 1] = a[j];
//             j--;
//         }

//         a[j + 1] = v;
//     }

//     printf("%d\n", a[1]);

//     return 0;
// }

// #include <stdio.h>

// #define MAX(a, b) a > b ? a : b
// #define MIN(a, b) a < b ? a : b

// int main() {
//     int a, b, c;

//     scanf("%d%d%d", &a, &b, &c);

//     int max = MAX(MAX(a, b), c);
//     int min = MIN(MIN(a, b), c);

//     printf("%d\n", a + b + c - max - min);

//     return 0;
// }
// < 