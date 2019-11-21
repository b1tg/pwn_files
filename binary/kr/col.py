import random

def get_char_int():
    return random.randrange(0x20,0x7f)
    # return chr(random.randrange(0x20,0x7f))

def asm_num():
    s = '0x'
    s1 = ''
    for i in range(0, 4):
        c = get_char_int()
        n = "{:x}".format(c)
        # print("c:",c)
        # print("n:",n)
        s += n 
        s1 += chr(c)
    
    return (int(s, 16),s1)

    # print(s)

# print(get_char_int())
# s=asm_num()

# print(s)

while True:
    s = 0
    l = []
    num = 0
    s1s = ''
    for i in range(0, 5):
        (num, s1) = asm_num()
        s1s+=(s1[::-1])
        s += num
        l.append(hex(num))
        if s > 0x100000000:
            s -= 0x100000000
    print("sum: ", hex(s), l, s1s)
    mask = 0xfffff000
    if (s&mask)^(0x21DD09EC&mask)==0:
        print('ok')
        break
        # print("sum: ", hex(s))
