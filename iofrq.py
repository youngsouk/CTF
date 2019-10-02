from pwn import *

p = remote('dets.kro.kr',  30006)

p.sendlineafter('key : ', '1')
p.sendlineafter('menu : ', '3')


p.interactive()
