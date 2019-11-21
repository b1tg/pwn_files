#include<stdio.h>

int main() {
    // char buf[20];
    char *buf;
    printf("show u the buf ptr: %p\n", buf);
    buf = malloc(0x20);

    read(0, buf, 10);
    printf("first read, show u the buf: %s\n", buf);

    read(0, buf, 10);
    printf("second read, show u the buf: %s\n", buf);



} 
