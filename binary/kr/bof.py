# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
r = process('./bof')
r.recvuntil('overflow me : \n')
gdb.attach(r)
pause()
r.sendline("ABC"*10)
r.interactive()


