#include<stdio.h>


int read_to_str(char *str, int len, char end_char)
{
  char buf; // [esp+1Bh] [ebp-Dh]
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i < len; ++i )
  {
    if ( read(0, &buf, 1) <= 0 )
      exit(-1);
    if ( buf == end_char )
      break;
    str[i] = buf;
  }
  str[i] = 0;
  return i;
}
void leave_name()
{
//int a;
  char name[64]; // [esp+1Ch] [ebp-5Ch]
  char *v2; // [esp+5Ch] [ebp-1Ch]
  int v3; // [esp+5Ch] [ebp-1Ch]
  //unsigned int v3; // [esp+6Ch] [ebp-Ch]

//  memset(name, 0, 0x50u);
  puts("Input your name:");
  read_to_str(name, 64, '\n');
printf("111\n");
 v2 = malloc(0x40u);
printf("211, %d\n", v3);

 // g_name = *(_DWORD *)v2;
  strcpy(v2, name);
printf("311\n");
printf("name: %p,%p %s\n", &name, name, name);
printf("v2: %p,%p %s\n", &v2, v2, v2);
//  welcome(*(int *)v2);
}
int main() {

	leave_name();
	printf("end\n");
__asm__("int $3");
//__asm__("int");
return 0;

}
