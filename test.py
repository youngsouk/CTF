from pwn import *

context.log_level = 'debug'

p = process('./test')
#p = remote('',)
e = ELF('./test')
l = e.libc
#l = ELF('./')

pause()

p.interactive()