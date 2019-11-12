import sys
from pwn import *

if len(sys.argv) != 2:
	print "sys.argv[1] = r : remote	l : local"
	exit()
	
context.log_level = 'debug'

if sys.argv[1].strip() == 'l':
	p = process('./printable')
elif sys.argv[1].strip() == 'r':
	p = remote('',)

e = ELF('./printable')

if sys.argv[1].strip() == 'l':
	l = e.libc
elif sys.argv[1].strip() == 'r':
	l = ELF('./')

pause()



p.interactive()