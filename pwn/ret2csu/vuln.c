#include <stdio.h>

int win(int x, int y, int z) {
    if(z == 0xdeadbeefcafed00d) {
        puts("Awesome work!");
    }
}

int main() {
    puts("Come on then, ret2csu me");

    char input[30];
    gets(input);
    return 0;
}