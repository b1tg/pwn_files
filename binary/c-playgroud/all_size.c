#include <stdio.h>
#define INTERNAL_SIZE_T size_t
/* The corresponding word size */
#define SIZE_SZ (sizeof(INTERNAL_SIZE_T))
int main() {
    printf("size_t size: %x\n", sizeof(size_t));
    printf("int size: %x\n", sizeof(int));
    printf("ulong size: %x\n", sizeof(unsigned long));
    printf("long int size: %x\n", sizeof(long int));
    printf("long long int size: %x\n", sizeof(long long int));
    printf("ptr size: %x\n", sizeof(int*));
    printf("signed int size: %x\n", sizeof(signed int));
    printf("unsigned int size: %x\n", sizeof(unsigned int));
}

