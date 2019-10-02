from pwn import *

def malloc(size, data):
    p.sendlineafter('Your choice :','1')
    p.sendlineafter('Size:', size(str))
    p.sendlineafter('Data:', str(data))

def free():
    p.sendlineafter('Your choice :','2')

context.log_level = "debug"

p = process('./tcache_tear')
e = ELF('./tcache_tear')
l = e.libc

for name,addr in e.got.items():
    log.info(name + ' : ' + hex(addr))



p.interactive()
