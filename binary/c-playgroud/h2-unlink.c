#include<stdio.h>
int main() {

	char* a= malloc(0x200);
	char* b= malloc(0x200);
	char* c= malloc(0x200);
	char* d= malloc(0x200);
	free(a);
	free(c);
	malloc(0x200);
}
