+- MENU -----------------------------------------------------------------------+
| [A] Add memo                                                                 |
| [D] Delete memo                                                              |
| [E] Edit memo                                                                |
| [Q] Quit                                                                     |
+------------------------------------------------------------------------------+
(CMD)>>> a

(SIZE)>>> 100 (0,256]
(CONTENT)>>> af

Added.


0x602040 tinypad

pwndbg> p &environ
$2 = (char ***) 0x7ffff7ffe100 <environ>
pwndbg> p/x 0x7fffffffe3e8-0x7ffff7ffe100
$3 = 0x80002e8
pwndbg> p __environ
$4 = (char **) 0x7fffffffe4d8
pwndbg> p &__environ
$5 = (char ***) 0x7ffff7ffe100 <environ>
pwndbg> p/x 0x7fffffffe4d8 - 0x7fffffffe3e8
$6 = 0xf0
pwndbg>


('environ_pointer: ', '0x7ffff7dd3f38')
('environ_addr: ', '0x7fffffffdcd8')
('main_ret_addr: ', '0x7fffffffdbe8')
