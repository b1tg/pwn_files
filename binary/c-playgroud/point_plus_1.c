// struct Ingre {
//     uint32 calory; // 0
//     char *name; // 8
//     uint32 price; // 32 * 1
 
//     uint32 price; // 32 * 35


// }; 

// maclloc(0x90) //0x90=144
// _DWORD uint32

#include <stdio.h>
typedef unsigned int    uint32;
#define _DWORD uint32
_DWORD *ingre_list; //32bit
typedef struct _Ingre { //144
    int calory; //0
    int price; // 4
    char name[132]; //offset 8
    _DWORD addr; //offset 35*4=140
}Ingre, *PIngre;

struct Recipe { //1036
    char *ingre_list //offset 0
    char *num_list //offset 4
    char name[116] // 8
    char dish_type[16] //31*4=124
    char *instruction//35*4=140  1036
    // int xxx //offset 16
    // char *xx //offset 32
    // char *type //offset 31*8=248

    // char *type //offset 124*4=496
}

int got_ingre(char *name)
{
  int v2; // [esp+4h] [ebp-14h]
  _DWORD *i; // [esp+8h] [ebp-10h]

  v2 = 0;
  for ( i = (_DWORD *)ingre_list; i && *i; i = (_DWORD *)i[1] )
  {
    if ( !strcmp((const char *)(*i + 8), name) )
      return v2;
    ++v2;
  }
  return -1;
}
int main() {
    // ingre_list[0] = 
    Ingre i;
    PIngre p = &i;
    p->price=10;
    
    printf("[*] addr of  Ingre -> %p\n", &i);
    printf("[*] price of  Ingre -> %d\n", p->price);
    printf("[*] sizeof  Ingre -> %d, %d\n", sizeof(i), sizeof(p));


}


void print_point_plus_1() {
    char *name = "abc";
    int num = 25;
    long lnum= 11111111;
    printf("[+] 1. show ptr addr\n");
    printf("\t[*] name@%p, name+1@%p, name+2@%p, name+3@%p\n", &name, name+1, name+2, name+3);
    printf("\t[*] num@%p, num+1@%p\n",&num, &num+1);
    printf("\t[*] lnum@%p, lnum+1@%p\n",&lnum, &lnum+1);
    printf("[+] 2. show type size\n");
    printf("\t[*] sizeof(xx), char->%d, int->%d, long->%d \n", sizeof(char), sizeof(int), sizeof(long));
}