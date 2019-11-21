#include<stdio.h>
int func1() {

  int v1; // [esp+18h] [ebp-30h]
  char s; // [esp+1Ch] [ebp-2Ch]
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  do
  {
    printf("Action: ");
   
    fgets(&s, 32, stdin);
  }
  while ( !__isoc99_sscanf(&s, "%u", &v1) );
  return v1;
}
int main() {
int a=1;
int b=2;

printf("res: %d", func1());

} 
