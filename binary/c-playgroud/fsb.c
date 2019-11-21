/* fsb.c */
//gcc -Wl,-z,relro,-z,now fsb.c -o fsb
/* fsb.c */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main()
{
    char buf[200];
    printf("[+] buf = %p\n", buf);
    read(0,buf,200);
    printf(buf);
    putchar('\n');
    return 0;
}

