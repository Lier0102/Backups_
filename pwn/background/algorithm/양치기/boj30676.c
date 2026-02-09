#include <stdio.h>

int main() {
    int w;
    scanf("%d", &w);

    if (w >= 620) {
        printf("Red\n");
    } else if (w >= 590) {
        printf("Orange\n");
    } else if (w >= 570) {
        printf("Yellow\n");
    } else if (w >= 495) {
        printf("Green\n");
    } else if (w >= 450) {
        printf("Blue\n");
    } else if (w >= 425) {
        printf("Indigo\n");
    } else {
        printf("Violet\n");
    }

    return 0;
}