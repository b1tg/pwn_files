# a='0x29642174+0x56617d54+0x43647d45+0x72787468+0x6c3a7977'

#0x77652130+0x7359672e+0x673b213c+0x687e3f22+0x67652130

a = '29642174'
res = ''
for a in ['77652130', '7359672e', '673b213c', '687e3f22', '67652130']:
    ts = ''
    for i in range(0,4):
        t=a[2*i:(2*i+2)]
        t = int(t, 16)
        t= chr(t)
        # print(t)
        ts+=t
    print(ts)
    res += ts[::-1]

print("res: ", res)



# )d!t Va}T Cd}E rxth l:yw
# t!d)T}aVE}dChtxrwy:l
# t\!d\)T}aVE}dChtxrwy:l