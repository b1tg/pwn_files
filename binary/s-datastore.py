# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

# r = remote('52.68.31.117', 9547)
r = process('./datastore_7e64104f876f0aa3f8330a409d9b9924.elf')

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
datastore = ELF("./datastore_7e64104f876f0aa3f8330a409d9b9924.elf")


print(str(r.proc.pid))

def dump():
    r.sendline('DUMP')

def get(key):
    r.sendline('GET')
    r.sendline(key)

def put(key, data):
    r.sendline('PUT')
    r.sendline(key)
    r.sendline(len(data))
    r.send(data)

def dd(key):
    r.sendline('DEL')
    r.sendline(key)  






print(str(r.proc.pid))
r.interactive()
