from pwn import *

s = ssh(user = 'unlink', host = 'pwnable.kr',port = 2222, password = 'guest')


