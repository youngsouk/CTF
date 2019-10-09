from pwn import *

context.log_level = 'debug'

def add(size,note):
    p.sendlineafter('>>> ', '1')
    p.senlineafter('size : ', str(size))
    p.sendafter('note : ', str(note))

def delete(idx):
    p.sendlineafter('>>> ', '2')
    p.sendlineafter("note idx : ", str(idx))

def edit(idx, note):
    p.sendlineafter('>>> ', '3')
    p.sendlineafter('note idx : ', str(idx))
    p.sendlineafter('note : ', str(note))

def view(idx):
    p.sendlineafter('>>> ', '4')
    p.sendlineafter('note idx : ', str(idx))


p = process('./safe_note')
e = ELF('./safe_note')
l = e.libc

pause()



p.interactive()
