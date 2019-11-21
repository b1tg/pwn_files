#include<stdio.h>
int main() {
	char* p1 = malloc(0x21);
	char* p2 = malloc(0x22);

	char* p3 = malloc(0x32);

    free(p1);
    free(p2);
    free(p3);

    char* p4 = malloc(0x23);
    char* p5 = malloc(0x24);
}
