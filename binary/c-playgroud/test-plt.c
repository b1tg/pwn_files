#include <stdio.h>
#include <unistd.h>
// gcc -m32 -g demo.c -o demo
int main()
{
    char data[20];
    read(0,data,20);
    return 0;
}
