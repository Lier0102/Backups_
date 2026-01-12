#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFSIZE 256

unsigned long mul, inc, seed;
unsigned long long minary;
void pop_rdi() {
    __asm volatile(
        "pop %rdi;\n"
        "ret");
}

int urandom_fd() {
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open");
        exit(1);
    }
    return fd;
}

unsigned int gen_random(int fd) {
    unsigned int ret;
    if (read(fd, &ret, sizeof(ret)) != sizeof(ret)) {
        perror("read");
        exit(1);
    }
    return ret;
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    int fd = urandom_fd();
    seed = gen_random(fd);
    mul = gen_random(fd);
    inc = gen_random(fd);
    close(fd);
}

unsigned long do_prng() {
    seed = (seed * mul + inc) & 0xFFFFFFFF;
    return seed;
}

unsigned long long gen_minary() {
    unsigned int high, low;
    high = do_prng();
    low = do_prng();
    return ((unsigned long long)high << 32) | low;
}

int main() {
    init();
    char buf[BUFSIZE];
    while(1) {
        memset(buf, 0, BUFSIZE);
        minary = gen_minary();
        *(unsigned long long *)(buf + BUFSIZE - 0x8) = minary;
        printf("Enter a string > ");
        read(0, buf, BUFSIZE + 0x40);
        if(!strncmp(buf, "quit", 4)) {
            if(*(unsigned long long *)(buf + BUFSIZE - 0x8) != minary) {
                puts("[!] Buffer overflow detected!");
                exit(0);
            }
            puts("Goodbye!");
            break;
        }
        printf("Your string: %s\n", buf);
    }

    return 0;
}