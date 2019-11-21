```c
struct Entry{ //64*3 = 32*6 = _DWORD*6 = 24*8
    int64 valid=1;// 
    int64 len; // offset = 64
    int64 data_enc; // offset = 2 * 64
}
```
load addr = 0x555555554000 

entry_array = x/10gx 0x00203060+0x555555554000
entry_array[n] = x/10gx 0x00203060 + 0x555555554000 + 24*n
x/10gx 0x00203060 + 0x555555554000 + 24*n


init_radom =0x29fae856d0c21ac9
x/10gx 0x00203048+0x555555554000

data = date_enc^init_radom

gdb-peda$ p/x  0x29fabd0385b79ad9^ 0x29fae856d0c21ac9
$5 = 0x555555758010

merge的时候不会用原来的id，会找一个空的id插进去


gdb-peda$ p &global_max_fast
$2 = (size_t *) 0x7ffff7dd37f8 <global_max_fast>
gdb-peda$ p/x 0x7ffff7dd37f8-$libc
$3 = 0x3c67f8
gdb-peda$

# find __realloc_hook TODO
gdb-peda$ x/1x $libc+0x3c4aed
0x7ffff7dd1aed <_IO_wide_data_0+301>:   0xfff7dd0260000000
gdb-peda$ x/10x $libc+0x3c4aed
0x7ffff7dd1aed <_IO_wide_data_0+301>:   0xfff7dd0260000000      0x000000000000007f
0x7ffff7dd1afd: 0xfff7a92e20000000      0xfff7a92a0000007f
0x7ffff7dd1b0d <__realloc_hook+5>:      0x000000000000007f      0x0000000000000000
0x7ffff7dd1b1d: 0x0000000000000000      0x0000000000000000
0x7ffff7dd1b2d <main_arena+13>: 0x0000000000000000      0x0000000000000000
gdb-peda$ x/10gx 0x7ffff7dd1b0d-0x5
0x7ffff7dd1b08 <__realloc_hook>:        0x00007ffff7a92a00      0x0000000000000000
0x7ffff7dd1b18: 0x0000000000000000      0x0000000000000000
0x7ffff7dd1b28 <main_arena+8>:  0x0000000000000000      0x0000000000000000
0x7ffff7dd1b38 <main_arena+24>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd1b48 <main_arena+40>: 0x0000000000000000      0x0000000000000000
gdb-peda$ p/x 0x7ffff7dd1b08 - $libc
$4 = 0x3c4b08