# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)


print(str(r.proc.pid))

gdb.attach(r, """
heap

""");
print(str(r.proc.pid))

r.interactive()

