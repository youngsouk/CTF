from pwn import *

context.log_level = 'debug'

p = process('./fixed')
#p = remote('',)
e = ELF('./fixed')
l = e.libc
#l = ELF('./')

pause()



p.interactive()
