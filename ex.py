from pwn import *
import sys
import re
import pdb

def init():
	global f_name
	buffer = ''
	buffer += "from pwn import *\n\n"

	buffer += "context.log_level = 'debug'\n\n"

	return buffer

def send_before_menu(p, before_menu):
	### send str before menu
	for tmp in before_menu:
		menu_content = ''
		try:
			menu_content += p.recv(timeout = 0.3)
			p.sendline(str(tmp))
		except:
			break
	########################

def print_menu_content(menu_content):
	length = len(menu_content[len(menu_content)/2]) + 7

	print '\x1b[1;35m' + 'This is menu_content'.center(length, '-') + '\x1b[1;m'
	for i in range(len(menu_content)):
		print '\x1b[1;31m{0:<2}\x1b[1;m'.format(i) + ' --> ' + menu_content[i]

def rename_menu_content(menu_content):
	print_menu_content(menu_content)
	print '\x1b[1;31mmenu_content is very important for this program. So make sure it is correct\x1b[1;m'
	accept = raw_input('Do you want to change menu_content? \x1b[1;32m(y/Y)\x1b[1;m ').strip()
	if accept == 'y' or accept == 'Y':
		while True:
			print_menu_content(menu_content)

			print 'which line do you want to delete? (\x1b[1;31mone number\x1b[1;m) \x1b[1;35mex) 5\x1b[1;m'
			print '\x1b[1;31m-1 is exit\x1b[1;m'
			line_idx = int(raw_input())
			if line_idx == -1:
				menu_content = '\n'.join(menu_content)
				return menu_content.strip()
			del menu_content[line_idx]
			print ''
	else:
		menu_content = '\n'.join(menu_content)
		return menu_content.strip()

def extract_function_name(menu_content):
	global r, r2, r3
	function_names = []
	tmps = r.findall(menu_content)
	for tmp in tmps:
		idx = r3.search(tmp).group()
		tmp = r2.sub('', tmp)
		function_name = tmp.strip().replace(' ', '_')
		function_names.append([str(idx), function_name])
	return function_names

def find_key(menu_content):
	return menu_content.split('\n')[-1]

def make_func(p, menu_content, key, function_names):
	global r2

	p.recvuntil(key)
	menu = ''

	for function_info in function_names:
		### find function params and conditions
		params = []
		params_conditions = []
		log.info('processing ' + function_info[1] + ' function')
		p.sendline(function_info[0])

		if(function_names[0] == function_info):
			p.recv(1)
		try:
			while True:
				tmp = p.recv(timeout = 0.3)
				if menu_content in tmp:
					break

				param = r2.sub('',tmp.strip()).strip().split(' ')[-1]
				params.append(param)
				params_conditions.append([tmp,param])

				content = 'plz input test param for ' + "\"\x1b[1;31m" + tmp + "\x1b[1;m\""
				print content
				test = raw_input('\x1b[1;36mparam : \x1b[1;m')
				p.sendline(str(test))
				print ''
		except EOFError:
			print 'Process is terminated'
			print 'It will be restarted'
			p = process('./' + f_name)
			### send str before menu
			for tmp in before_menu:
				try:
					p.recv(timeout = 0.3)
					p.sendline(str(tmp))
				except:
					break
			p.recvuntil(key)
			p.recv(1)
			continue
			########################
		except:
			print 'exception occured...'
			print 'I guess you typed wrong argument'
			print 'switch to next function...'
			continue
		###########################
		#print params_conditions
		tmp = 'def ' + function_info[1] + '(' + ', '.join(params) + '):\n'	
		tmp += "	p.recvuntil('" + key + "')\n"
		tmp += "	p.sendline('" + function_info[0] + "')\n\n"
		for param_condition in params_conditions:
			tmp += "	p.sendlineafter('" + param_condition[0] + "', " + param_condition[1] + ")\n"
		menu += tmp
	p.close()
	return menu

def menu_build():
	global f_name

	if(len(sys.argv) >= 4):
		before_menu = sys.argv[3:]

	p = process('./' + f_name)
	#context.log_level = "debug"
	
	send_before_menu(p, before_menu)
	menu_content = p.recv().strip()
	menu_content = rename_menu_content(menu_content.split('\n'))

	function_names = extract_function_name(menu_content)

	key = find_key(menu_content)
	print "key string is : \"" + key + "\" "
	p.close()

	### make menu funciton
	p = process('./' + f_name)
	send_before_menu(p, before_menu)
	menu = make_func(p, menu_content, key, function_names)
	return menu

def setup():
	global f_name
	buffer = ''

	buffer += "p = process('./" + str(f_name) + "')\n"
	buffer += "#p = remote('',)\n"
	buffer += "e = ELF('./" + str(f_name) + "')\n"
	buffer += "l = e.libc\n"
	buffer += "#l = ELF('./')\n\n"
	buffer += '\n'

	return buffer

def useful_plt_got():
	global f_name
	e = ELF('./' + f_name)

	buffer = ''
	useful = ['printf', 'puts', 'gets', 'open', 'read', 'write', 'malloc', 'free', 'system']
	for n, addr in e.plt.items():
		if n in useful:
			buffer += n + "_plt = " + str(hex(addr)) + '\n'

	buffer += '\n'

	for n, addr in e.got.items():
		if n in useful:
			buffer += n + "_got = " + str(hex(addr)) + '\n'

	buffer += '\n'

	return buffer

def find_p_rdi_r():
	global f_name
	r = process('/bin/bash')
	r.sendline("ROPgadget --binary " + f_name + " | grep \"pop rdi ; ret\"")
	addr = r.recvuntil(':')
	r.close()

	buffer = ''
	buffer += "p_rdi_r = " + addr[0:18]
	buffer += '\n'

	return buffer

if __name__ == '__main__':
	r = re.compile(r'[0-9]+.+\n') # function content line
	r2 = re.compile(r'[^a-zA-Z\s]+') # function name
	r3 = re.compile(r'[0-9]+') # function idx

	if len(sys.argv) < 2:
		print "usage : ex.py [filename]"
		exit()
	f_name = sys.argv[1]

	py_name = str(f_name) + '.py'
	f = open(py_name, 'w')

	content = ''
	content += init()

	### menu build
	if len(sys.argv) >= 3:
		if str(sys.argv[2]) == 'menu':
			content += menu_build()
	###############
	content += setup()
	### useful plt and got
	content += useful_plt_got()
	####################
	#useful gadget : pop rdi ; ret;
	content += find_p_rdi_r()
	####################
	content += "pause()\n\n"
	content += "p.interactive()"

	f.write(content)
