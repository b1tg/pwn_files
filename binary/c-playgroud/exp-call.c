#include<stdio.h>

void vuln(int a, int b){
	printf("%d,%d",a,b);
}
int main() {

	vuln(1,2);
	system("/bin/sh");
}

