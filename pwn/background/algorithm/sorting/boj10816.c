// #include <stdio.h>

// int a[20000001];

// int main() {
//     int n, m;

//     scanf("%d", &n);

//     for (int i = 0; i < n; i++) {
//         int v;

//         scanf("%d", &v);
//         a[v + 10000000]++;
//     }

//     scanf("%d", &m);
    
//     for (int i = 0; i < m; i++) {
//         int v;

//         scanf("%d", &v);
//         printf("%d ", a[v + 10000000]);
//     }

//     return 0;
// }

// #include <stdio.h>
// #include <stdlib.h>

// int comp(const void *a, const void *b) {
//     return (*(int *)a) - (*(int *)b);
// }

// int upper(int a[], int n, int target) {
//     int l = 0, r = n;
    
//     while (l < r) {
//         int mid = l + (r - l) / 2;

//         if (a[mid] <= target) {
//             l = mid + 1;
//         } else {
//             r = mid;
//         }
//     }

//     return l;
// }

// int lower(int a[], int n, int target) {
//     int l = 0, r = n;

//     while (l < r) {
//         int mid = l + (r - l) / 2;
         
//         if (a[mid] < target){
//             l = mid + 1;
//         } else {
//             r = mid;
//         }
//     }

//     return l;
// }

// int main(void) {
//     int n, m;
//     int a[500001];

//     scanf("%d", &n);

//     for (int i = 0; i < n; i++) {
//         scanf("%d", &a[i]);
//     }

//     qsort(a, n, sizeof(int), comp);

//     scanf("%d", &m);

//     for (int i = 0; i < m; i++) {
//         int v;

//         scanf("%d", &v);

//         int cnt = upper(a, n, v) - lower(a, n, v);
//         printf("%d ", cnt);
//     }

//     return 0;
// }