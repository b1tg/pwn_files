#include<stdio.h>

int main() {


	char* a = malloc(-10);

	printf("a-> %p", &a);
}
