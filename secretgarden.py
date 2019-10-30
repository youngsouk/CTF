from pwn import *

context.log_level = 'debug'

def raise(name, flower, flower):
	p.sendlineafter('Your choice :', '1')

	p.sendlineafter('Length of the name :', str(name))
	p.sendlineafter('The name of flower :', str(flower))
	p.sendlineafter('The color of the flower :', str(flower))

def visit():
	p.sendlineafter('Your choice :', '2')


def remove(garden):
	p.sendlineafter('Your choice :', '3')

	p.sendlineafter('Which flower do you want to remove from the garden:', str(garden))

def clean():
	p.sendlineafter('Your choice :', '4')


def leave():
	p.sendlineafter('Your choice :', '5')


p = process('./secretgarden')
#p = remote('',)
e = ELF('./secretgarden')
l = e.libc
#l = ELF('./')

pause()

raise

p.interactive()
