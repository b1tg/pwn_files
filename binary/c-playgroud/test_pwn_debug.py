from pwn_debug import *

## step 1
pdbg=pwn_debug("test-fopen")

pdbg.context.terminal=['tmux', 'splitw', '-h']

## step 2
pdbg.local("libc.so.6")
pdbg.debug("2.23")
#pdbg.remote('34.92.96.238',10000)
## step 3

#p=pdbg.run("debug")
#p=pdbg.run("remote")

# pause()
pdbg.bp([0x400450])

p=pdbg.run("local")
p.interactive()
