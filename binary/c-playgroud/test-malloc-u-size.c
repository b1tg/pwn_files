#include <stdio.h>
#include <stdint.h>
#include  <stdlib.h>

int main()
{
    char *a = malloc(0x10);
    printf("malloc 0x10, at %p, 0x%x \n", &a, a);
    int b = malloc_usable_size(a);
    printf("usable_size: 0x%x\n", b);

    return 0;
}
