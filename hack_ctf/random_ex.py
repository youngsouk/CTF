from pwn import *
from ctypes import *

p = remote('ctf.j0n9hyun.xyz', 3014)

clib = cdll.LoadLibrary('libc.so.6')

clib.srand(clib.time('\x00'))
p.sendline(str(clib.rand()))

p.interactive()
