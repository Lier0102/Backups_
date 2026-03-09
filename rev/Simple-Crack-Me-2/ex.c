#include <stdio.h>
#include <string.h>

void Xor(char *input, char *p) {
    size_t a;
    int i;

    a = strlen(p);

    for (i = 0; i < 0x20; i++) {
        input[i] = p[(unsigned long)(long)i % a] ^ input[i];
    }
    return;
}

void Inc(char *input, char p) {
    int i;

    for (i = 0; i < 0x20; i++) {
        input[i] = p + input[i];
    }

    return;
}

void Dec(char *input, char p) {
    int i;

    for (i = 0; i < 0x20; i++) {
        input[i] = input[i] - p;
    }

    return;
}

void decode(char *cipher) {
    Xor(cipher, "\x11\x33\x55\x77\x99\xbb\xdd");
    Dec(cipher, -13); // 0xd == 13
    Inc(cipher, 77); // M, 0x4d == 64 + 13 == 77
    Xor(cipher, "\xef\xbe\xad\xde"); // 0xdeadbeef
    Inc(cipher, 90); // 0x5a = 80 + 10 = 90
    Dec(cipher, 31); // 0x1f = 16 + 15
    Xor(cipher, "\xde\xad\xbe\xef");

    return;
}

int main() {
    char data[] = "\xf8\xe0\xe6\x9e\x7f\x32\x68\x31\x05\xdc\xa1\xaa\xaa\x09\xb3\xd8\x41\xf0\x36\x8c\xce\xc7\xac\x66\x91\x4c\x32\xff\x05\xe0\xd9\x91\x00";

    decode(data);
    printf("REAL FLAG: %s", data);

    return 0;
}