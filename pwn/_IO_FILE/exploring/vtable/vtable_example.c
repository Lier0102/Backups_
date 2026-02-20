#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    puts("You Win!");
}

int main(int argc, char **argv) {
    printf("win func is located at: %p\n", win);
    printf("puts is located at: %p\n", puts);

    FILE *fp = fopen("/dev/null", "w");

    char buf[0x1000];
    printf("Reading into stack buf located at: %p\n", buf);
    read(0, buf, 0x1000);

    puts("Reading over file pointer\n");
    read(0, fp, 0x100);

    puts("Calling fwrite!");
    fwrite(buf, 1, 10, fp);

    exit(0);
}