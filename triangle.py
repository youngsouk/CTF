from pwn import *
from string import *
from decimal import Decimal

p = remote('218.158.141.199', 24763)

context.log_level = "debug"

p.recvuntil('Step : ')
p.recvline()

x = []
y = []
t = []

cross = []

def solve_1():
	p.recvuntil('Step')
	p.recvline()
	p.recvline()

	for i in range(3):
	 	ap()

def ap():
	x.append(Decimal(p.recvuntil('x').strip('')[:-1]))

	p.recvuntil('+')
	y.append(Decimal(p.recvuntil('y').strip('')[:-1]))

	p.recvuntil('=')
	t.append(-1 * Decimal(p.recvuntil('\n').strip('')[:-1]))


def crossplot():
	for i in range(3):
		tmp = []

		c_x = y[i] * t[(i+1) % 3]
		c_x -= y[(i+1) % 3] * t[i]
		div = x[i] * y[(i+1) % 3] 
		div -= x[(i+1) % 3] * y[i]
		c_x /= div

		tmp.append(c_x)

		c_y = x[i] * c_x + t[i]
		c_y /= -1 * y[i]

		tmp.append(c_y)
		cross.append(tmp)

def width(cross):
	a = cross[0][0]
	b = cross[0][1]

	cross[0][0] -= a
	cross[0][1] -= b

	cross[1][0] -= a
	cross[1][1] -= b

	cross[2][0] -= a
	cross[2][1] -= b
	
	width = cross[1][0] * cross[2][1]
	width -= cross[1][1] * cross[2][0]
	width /= 2
	width = abs(width)
	print width

	x = []
	y = []
	t = []
	cross = []

	return str(width)

for i in range(100):
	solve_1()
	print x
	print y
	print t

	crossplot()
	print cross

	p.recv()
	p.sendline(width(cross))

	x = []
	y = []
	t = []
	cross = []


p.interactive()
