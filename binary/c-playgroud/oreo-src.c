#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef unsigned int    uint32;
#define _DWORD uint32


char *current; //0804A288
int order_count; //dword_804A2A0
int rifle_count; // dword_804A2A4
// int 
char dword_804A2A8[500]; //不知道是啥 dword_804A2A8
// char *unk_804A2C0; //不知道是啥 

struct rifle {
    char desc[0x19]; // 0x19=25
    char name[0x1b]; //ox1b=27 offset 25
    char *pre_add; // offset 52=0x34
};
int sub_8048896()
{
  int v1; // [esp+18h] [ebp-30h]
  char s; // [esp+1Ch] [ebp-2Ch]
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

//   v3 = __readgsdword(0x14u);
  do
  {
    printf("Action: ");
// printf("fuck\n");
   
    fgets(&s, 32, stdin);
  }
  while ( !__isoc99_sscanf(&s, "%u", &v1) );
  return v1;
}
sub_80485EC(const char *a1)
{
  size_t v1; // edx
  char *v3; // [esp+28h] [ebp-10h]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

//   v4 = __readgsdword(0x14u);
  v1 = strlen(a1) - 1;
  v3 = (char *)&a1[v1];
  if ( &a1[v1] >= a1 && *v3 == 10 )
    *v3 = 0;
//   return __readgsdword(0x14u) ^ v4;
}

unsigned int add_sub_8048644()
{
  char *v1; // [esp+18h] [ebp-10h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

//   v2 = __readgsdword(0x14u);
  v1 = current;
  current = (char *)malloc(0x38u);
  if ( current )
  {
    *((_DWORD *)current + 13) = v1; //13*4=52
    printf("Rifle name: ");
    fgets(current + 25, 56, stdin);
    sub_80485EC(current + 25);
    printf("Rifle description: ");
    fgets(current, 56, stdin);
    sub_80485EC(current);
    ++rifle_count;
  }
  else
  {
    puts("Something terrible happened!");
  }
//   return __readgsdword(0x14u) ^ v2;
}


unsigned int show_sub_8048729()
{
  char *i; // [esp+14h] [ebp-14h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

//   v2 = __readgsdword(0x14u);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = current; i; i = (char *)*((_DWORD *)i + 13) )
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
//   return __readgsdword(0x14u) ^ v2;
    return 0;
}

unsigned int order_sub_8048810()
{
  char *ptr; // ST18_4
  char *v2; // [esp+14h] [ebp-14h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

//   v3 = __readgsdword(0x14u);
  v2 = current;
  if ( rifle_count )
  {
    while ( v2 )
    {
      ptr = v2;
      v2 = (char *)*((_DWORD *)v2 + 13);
      free(ptr);
    }
    current = 0;
    ++order_count;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
//   return __readgsdword(0x14u) ^ v3;
    return 0;
}

unsigned int msg_sub_80487B4()
{
  unsigned int v0; // ST1C_4

//   v0 = __readgsdword(0x14u);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(dword_804A2A8, 128, stdin);
  sub_80485EC(dword_804A2A8);
//   return __readgsdword(0x14u) ^ v0;
    return 0;
}

unsigned int status_sub_8048906()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

//   v1 = __readgsdword(0x14u);
  puts("======= Status =======");
  printf("New:    %u times\n", rifle_count);
  printf("Orders: %u times\n", order_count);
  if ( *dword_804A2A8 )
    printf("Order Message: %s\n", dword_804A2A8);
  puts("======================");
//   return __readgsdword(0x14u) ^ v1;
    return 0;
}

unsigned int sub_804898D()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

//   v1 = __readgsdword(0x14u);
  puts("What would you like to do?\n");
  printf("%u. Add new rifle\n", 1);
  printf("%u. Show added rifles\n", 2);
  printf("%u. Order selected rifles\n", 3);
  printf("%u. Leave a Message with your Order\n", 4);
  printf("%u. Show current stats\n", 5);
  printf("%u. Exit!\n", 6);
  printf("xxx\n");
  while (1)
  {
    //   printf("1111\n");
    switch ( sub_8048896() )
    {
      case 1:
        add_sub_8048644();
        break;
      case 2:
        show_sub_8048729();
        break;
      case 3:
        order_sub_8048810();
        break;
      case 4:
        msg_sub_80487B4();
        break;
      case 5:
        status_sub_8048906();
        break;
      case 6:
        // return __readgsdword(0x14u) ^ v1;
      default:
        continue;
    }
  }
}
int main()
{
  rifle_count = 0;
  order_count = 0;
//   dword_804A2A8 = (char *)&unk_804A2C0;
  puts("Welcome to the OREO Original Rifle Ecommerce Online System!");
  puts(
    "\n"
    "     ,______________________________________\n"
    "    |_________________,----------._ [____]  -,__  __....-----=====\n"
    "                   (_(||||||||||||)___________/                   |\n"
    "                      `----------'   OREO [ ))\"-,                   |\n"
    "                                           \"\"    `,  _,--....___    |\n"
    "                                                   `/           \"\"\"\"\n"
    "\t");
  sub_804898D();
  return 0;
}


