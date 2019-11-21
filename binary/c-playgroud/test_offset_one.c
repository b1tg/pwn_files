/*
说明： off-by-one漏洞分析
取自2015 plaidctf datastore .text:0000000000001040
创建日期：19.10.6


*/

#include<stdio.h>
#include<stdlib.h>
#include <malloc.h>
char* getkey()
{
  char *buf; // r12
  char *buf_tmp; // rbx
  size_t cap; // r14
  char chr; // al
  char chr_tmp; // bp
  int offset; // r13
  char *new_buf; // rax

  buf = (char *)malloc(8uLL);

  char* next = malloc(0x140);
  buf_tmp = buf;
  cap = malloc_usable_size(buf);
  printf("cap: %d\n",cap);
  printf("some ptr: %p, %p\n", buf, next);
  while ( 1 )
  {
    chr = getc(stdin);
    chr_tmp = chr;
    if ( chr == -1 ) {
        puts("do exit");
        exit(-1);
    }
    if ( chr == '\n' )
      break;
    offset = buf_tmp - buf;
    if ( cap <= buf_tmp - buf )
    {
      new_buf = (char *)realloc(buf, 2 * cap);
      buf = new_buf;
      if ( !new_buf )
      {
        puts("FATAL: Out of memory");
        exit(-1);
      }
      buf_tmp = &new_buf[offset];
      cap = malloc_usable_size(new_buf);
    }
    *buf_tmp++ = chr_tmp;
  }
  *buf_tmp = 0;
  return buf;
}


void main() {
    printf("start\n");
    char* key = getkey();
    printf("getkey done\n");
    printf("i got the key: @%p => %s\n", key, key);
    return;
}
/*



注意 0x602430+0x8处的低八位被覆盖，
$ perl -e 'print "A"x24 . "\x0a"   '> payload
gdb-peda$ r < payload
Starting program: /vagrant/pwn/binary/test_offset_one < payload
start
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 2, 0x0000000000400773 in getkey ()
gdb-peda$ x/20gx 0x602400
0x602400:       0x0000000000000000      0x0000000000000000
0x602410:       0x0000000000000000      0x0000000000000021
0x602420:       0x0000000000000000      0x0000000000000000
0x602430:       0x0000000000000000      0x0000000000000151
0x602440:       0x0000000000000000      0x0000000000000000
0x602450:       0x0000000000000000      0x0000000000000000
0x602460:       0x0000000000000000      0x0000000000000000
0x602470:       0x0000000000000000      0x0000000000000000
0x602480:       0x0000000000000000      0x0000000000000000
0x602490:       0x0000000000000000      0x0000000000000000
gdb-peda$ c
Continuing.
cap: 24
some ptr: 0x602420, 0x602440
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400876 in getkey ()
gdb-peda$ x/20gx 0x602400
0x602400:       0x0000000000000000      0x0000000000000000
0x602410:       0x0000000000000000      0x0000000000000021
0x602420:       0x4141414141414141      0x4141414141414141
0x602430:       0x4141414141414141      0x0000000000000100
0x602440:       0x0000000000000000      0x0000000000000000
0x602450:       0x0000000000000000      0x0000000000000000
0x602460:       0x0000000000000000      0x0000000000000000
0x602470:       0x0000000000000000      0x0000000000000000
0x602480:       0x0000000000000000      0x0000000000000000
0x602490:       0x0000000000000000      0x0000000000000000
gdb-peda$ info br
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000400876 <getkey+336>
        breakpoint already hit 1 time
2       breakpoint     keep y   0x0000000000400773 <getkey+77>
        breakpoint already hit 1 time
gdb-peda$ 

*/