#include<stdio.h>
int main() {
	printf("0x%x\n", (int *)0x8-(int*)0x0);
	printf("0x%x\n", (char *)0x8-(char*)0x0);
	printf("0x%x\n", (int *)0x8-(char*)0x0);
}