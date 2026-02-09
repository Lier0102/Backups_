#include <stdio.h>
#include <string.h>

int main() {
    char s[20];
    scanf("%s", s);
    
    if (strcmp(s, "SONGDO") == 0) {
        printf("HIGHSCHOOL\n");
    } else if (strcmp(s, "CODE") == 0) {
        printf("MASTER\n");
    } else if (strcmp(s, "2023") == 0) {
        printf("0611\n");
    } else if (strcmp(s, "ALGORITHM") == 0) {
        printf("CONTEST\n");
    }

    return 0;
}