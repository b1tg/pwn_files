#include <stdio.h>


int main() {

    char *ptr;
    char ptrz[10]={0};;
    int n=5;
    int i=0;
    ptr = ptrz;

    //  i = fread(ptr, 1, n, stdin);
    //  printf("in for, i: %d\n", i);
    //  ptr+=3;
    //  i = fread(ptr, 1, n, stdin);
    //  printf("in for, i: %d\n", i);

    // for(i=0;i>=0;i++)
  for ( i = fread(ptr, 1uLL, n, stdin); i > 0; i = fread(ptr, 1uLL, n, stdin) )
  {
      printf("in for, i: %d\n", i);
    ptr += i;
    n -= i;

    // i = fread(ptr, 1uLL, n, stdin);
    // printf("in for, i: %d\n", i);
  }

  printf("end of main, %d, %d, %s\n", n, i, ptr);
printf("ok");


}