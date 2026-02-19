#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    char buf[0x1000];

    int fd = open("/dev/urandom", O_RDONLY);
    for (int i = 0; i < 50000; i++) {
        read(fd, buf, 0x20);
    }
    
    return 0;
}