# -*- coding:utf-8 -*-
#!/usr/bin/env python
from pwn import *
#context.log_level = 'debug'

#context.terminal = ['tmux', 'splitw', '-h']
# r = remote('52.68.31.117', 9547)
    
payload =  ')d!tVa}TCd}Erxthl:yw'
#payload =  't!d)Va}TCd}Erxthl:yw'
r = process(['./col32', payload])
if 'wrong' not in r.recvline():
    print("[*] got it!!!", payload)
    r.kill()
else:
    r.kill()
    #print("[*] fail")



r.interactive()



