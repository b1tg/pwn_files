#include<stdio.h>


void main() {

	char* a = malloc(10);
	free(a);
	free(a);
	printf("never reach me");
}
