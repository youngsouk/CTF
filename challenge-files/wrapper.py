#!/usr/bin/python

import tempfile
import sys,os

if __name__ == "__main__":
	try:
		print("length of your file?")

		size = int(sys.stdin.readline())
		if size > 0x1000000:
			print("size is too big!")
			exit(-1)
		pay = sys.stdin.read(size)
		f = tempfile.NamedTemporaryFile(prefix='',delete=False)
		f.write(pay)
		f.close()

		print("now we will run yara on your file...")

		os.system("yara /home/ytf/rule %s"%f.name)
		print("done!")
		os.unlink(f.name)
	except:
		print("error!")


