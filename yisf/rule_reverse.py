from pwn import *

p = remote('218.158.141.182', 52387)

dic = {}
height = 0

def make_dic():
	for i in range(height):
		p.recvuntil('\'')
		key = p.recv(1)
		p.recv(1)

		p.recvuntil('\'')
		value = p.recvuntil('\'').strip().replace('\'','')
		dic[value] = key
def solve():
	global height

	p.recvuntil('Step :')
	p.recvline()
	p.recvline()
	bi = p.recvline()
	print bi
	
	p.recvuntil('= ')
	height = int(p.recvline().strip())
	p.recvuntil('table : ')
	p.recvuntil('{')

	make_dic()
	print dic
	
	p.recv()
	payload = ''
	k = 0
	i = 0
	while(i < len(bi)):
#		print i
#		print bi[k:i+1]
		while(len(dic.get(bi[k:i+1],'')) == 0):
			if(i >len(bi)):
				break
#print i
#print bi[k:i+1]
			i+=1

		payload += dic.get(bi[k:i+1], '')
		print payload
		k = i+1
#	print payload
	return str(payload)
#	print payload


for i in range(100):
	p.sendline(solve())

p.interactive()
