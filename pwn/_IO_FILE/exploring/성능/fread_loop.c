#include <stdio.h>

int main(int argc, char **argv) {
    char buf[0x1000];
    FILE *fp = fopen("/dev/urandom", "r");

    for (int i = 0; i < 50000; i++) {
        fread(buf, 1, 0x20, fp);
    }
    
    return 0;
}