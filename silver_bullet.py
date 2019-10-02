from pwn import *

def create(daat):
	p.sendlineafter('Your choice :', '1')
	p.sendafter('Give me your description of bullet :', str(data))

def powerup(data):
	p.sendlineafter('Your choice :', '2')
	p.sendafter('Give me your another description of bullet :', str(data))

def beat():
	p.sendlineafter('Your choice :', '3')

p = process('./silver_bullt')
e = ELF('./silver_bullt')
l = e.libc

context.log_level = "debug"

pause()




p.interactive()
