from pwn import *

context.log_level = 'debug'

def add(size, note):
	p.sendafter('>>>', '1')

	p.sendafter('size :', str(size))
	p.sendafter('note :', str(note))

def delete(idx):
	p.sendafter('>>>', '2')

	p.sendafter('note idx :', str(idx))

def edit(idx, note):
	p.sendafter('>>>', '3')

	p.sendafter('note idx :', str(idx))
	p.sendafter('note :', str(note))

def view(idx):
	p.sendafter('>>>', '4')

	p.sendafter('note idx :', str(idx))

p = process('./safe_note')
#p = remote('',)
e = ELF('./safe_note')
l = e.libc
#l = ELF('./')

pause()

#add(200, 'a')
#add(200, 'a' * 8)
#delete(0)
#view(0)

p.interactive()
