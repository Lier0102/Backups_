#include <stdio.h>
#include <unistd.h>

int win_var = 0;

void win() {
    puts("You win!");
}

int main(int argc, char **argv) {
    printf("win_var is located at: %p\n", &win_var);

    FILE *fp = fopen("./secret_file", "r");

    read(0, fp, 0x100);

    char buf[256];
    puts("Calling fread!");
    fread(buf, 1, 10, fp);

    if (win_var) {
        win();
    }
}