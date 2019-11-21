# re

```c

struct Item {
 int64* a //8*16
 int64* b //8*24
}

struct heap//16
{
  __int64 m_heap;
  __int64 m_size;
};

struct global
{
  heap chunk[18];
};

global heap_mem; //24bytes?

heap_mem[2-17]
 和0 xor 还是自身， 0^1=1, 0^0=0

```
pwndbg> p/x *(long long *)0x13370800
$10 = 0xb27eff9d684e8361
pwndbg> set $k1 = *(long long *)0x13370800
pwndbg> p/x $k1
$11 = 0xb27eff9d684e8361
pwndbg> set $k2 = *(long long *)0x13370808
pwndbg> p/x $k2
$12 = 0xf8cb060bb84b6b10
pwndbg>

```md
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
        0x13370000         0x13371000 rw-p     1000 0 <<< **这里是mmap分配出来的**
    0x555555554000     0x555555556000 r-xp     2000 0      /vagrant/pwn/tmp/sakura_ctf_pwn/0ctf2018/heapstorm2/heapstorm2
    0x555555755000     0x555555756000 r--p     1000 1000   /vagrant/pwn/tmp/sakura_ctf_pwn/0ctf2018/heapstorm2/heapstorm2
    0x555555756000     0x555555757000 rw-p     1000 2000   /vagrant/pwn/tmp/sakura_ctf_pwn/0ctf2018/heapstorm2/heapstorm2
    0x555555757000     0x555555778000 rw-p    21000 0      [heap]
    0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dd1000     0x7ffff7dd3000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dd3000     0x7ffff7dd7000 rw-p     4000 0
    0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7fea000     0x7ffff7fed000 rw-p     3000 0
    0x7ffff7ff7000     0x7ffff7ffa000 r--p     3000 0      [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000 0      [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000 0
    0x7ffffffdd000     0x7ffffffff000 rw-p    22000 0      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]

```





# Q&A
升级时0<v5<=size-12，为什么??