#include<stdio.h>
#include<string.h>
int main()
{
  char s[100];
  long size;
  fgets(&s, 16, stdin);
  size = atoll(&s);
  printf("size: %ld", size);
  puts("ok");
  puts("ok");
}