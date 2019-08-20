from pwn import *
import base64

tmp = open('tmp', 'wb')
pause()

#context.log_level = "debug"

p = remote('192.168.0.123', 7777)

for i in range(0,100):
	p.recvuntil('Stage')
	p.recvline()
	p.recvline()
	
	
	buf = p.recvuntil('==').strip().replace('\n','')
	buf = buf.replace(' ', '')
	buf = base64.b64decode(buf)

	buf_l = list(buf)
	
	for i in range(0,len(buf),2):
		print buf[i: i+2]
		tmp.write(chr(int(buf[i: i+2],16)))

