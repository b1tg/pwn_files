import sys
import r2pipe

r2 = r2pipe.open("./zwiebel")
r2.cmd("e dbg.profile=zwiebel.rr2")
r2.cmd("doo") # reopen for debugging
r2.cmd("db 0x400875") # set breakpoint at `call r14`
r2.cmd("dc") # continue until breakpoint is hit

def step():
    r2.cmd("ds") # step one instruction
    r2.cmd("sr rip") # seek to current RIP value

# flag memory
flag = [0x20]*50

while True:
    # extract the assembler lines for the flag check
    # 0x7ffff7fc10d1    mov    al, byte ptr [rax + 0x15]
    # 0x7ffff7fc10d4    and    al, 0x10
    # 0x7ffff7fc10d6    je     0x7ffff7fc10ee
    disass = []
    while True:
        step()
        current_instruction = r2.cmdj("pdj 1")[0]
        disass.append(current_instruction['opcode'])
        if current_instruction['type'] == 'cjmp':
            break

    # parse the flag check rules from assembler
    offset = disass[-3].split("rax")[1][:-1]
    if not offset:
        offset = "0"
    offset = int(offset, 16)
    and_value = int(disass[-2].split(", ")[1], 16)
    if "je" in disass[-1]:
        flag[offset] = flag[offset] | and_value
        r2.cmd("dr zf=0")
    elif "jne" in disass[-1]:
        flag[offset] = flag[offset] & (0xFF ^ and_value)
        r2.cmd("dr zf=1")

    # print current flag
    out = ""
    for c in flag:
        if c >= 0x20 and c <= 0x7E:
            out += chr(c)
        else:
            out += " "
    sys.stdout.write("\r"+out)
    sys.stdout.flush()

    step() # follow the jump
    # continue until the `loop` instruction
    while True:
        step()
        if "loop" in r2.cmdj("pdj 1")[0]['opcode']:
            break
    # instruction after the `loop` is the next jmp into the
    # decrypted code
    target = hex(r2.cmdj("pdj 2")[1]['jump'])
    r2.cmd("db "+target)
    r2.cmd("dc")
