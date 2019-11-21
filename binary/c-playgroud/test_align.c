#include<stdio.h>
#include <emmintrin.h> //Required for mm_malloc
#define ALIGN 64

int main() {

  char name[64]="abc"; // [esp+1Ch] [ebp-5Ch]
  char *v2=_mm_malloc(sizeof(int), ALIGN);
//  char *v2="abc2"; // [esp+5Ch] [ebp-1Ch]
 // char *v3="abc3"; // [esp+5Ch] [ebp-1Ch]
  //char *v4="abc4"; // [esp+5Ch] [ebp-1Ch]
  
	printf("name: %p,%p %s\n", &name, name, name);
	printf("v2: %p,%p %s\n", &v2, v2, v2);
//	printf("v3: %p,%p %s\n", &v3, v3, v3);
//	printf("v4: %p,%p %s\n", &v4, v4, v4);
	
	return 0;


}
