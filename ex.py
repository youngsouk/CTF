import sys

if len(sys.argv) < 2:
		print "usage : ex.py [filename]"
		exit()
py_name = str(sys.argv[1]) + '.py'
f = open(py_name, 'w')

content = ''
content += "from pwn import *\n\n"

content += "context.log_level = 'debug'\n\n"

content += "p = process('./" + str(sys.argv[1]) + "')\n"
content += "#p = remote('',)\n"
content += "e = ELF('./" + str(sys.argv[1]) + "')\n"
content += "l = e.libc\n"
content += "#l = ELF('./')\n\n"

content += "pause()\n\n"

content += "p.interactive()"


f.write(content)
