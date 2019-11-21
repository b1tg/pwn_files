#include<stdio.h>
int main() {
	int* e;
	int father[10]={1,2,3,4,5,6,6,6,6,9};
	e = father;

	printf("0x%x\n", e);
	printf("0x%x\n", e[0]);
	printf("0x%x\n", e[2]);
	printf("0x%x\n", &e[2]);
	printf("0x%x\n", e+2-1);
	printf("0x%x\n", *(e+2-1));// debug this.
	printf("0x%x\n", &e[2]-e);
}
