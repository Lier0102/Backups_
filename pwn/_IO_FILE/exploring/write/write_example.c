#include <stdio.h>
#include <unistd.h>

char secret_message[] = "SECRET_BANKAI";

int main(int argc, char **argv) {
    printf("secret message is located at: %p\n", &secret_message);

    FILE *fp = fopen("/dev/null", "w");
    read(0, fp, 0x100);

    char buf[0x100];
    puts("Calling fwrite!");
    fwrite(buf, 1, 40, fp);

    return 0;
}