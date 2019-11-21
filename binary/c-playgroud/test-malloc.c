#include<stdio.h>

int main() {
	char *a = malloc(10);
	char *b = malloc(0x100);
	printf("stack: a=> %p, b=> %p\n", &a, &b);
	printf("heap: a=> 0x%x, b=> 0x%x\n", a, b);
	return 0;
}
