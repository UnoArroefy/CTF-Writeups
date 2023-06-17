# rev
## the-sandbox

### Description

![Desc](https://raw.githubusercontent.com/UnoArroefy/CTF-Writeups/main/nahamcon2023/the-sandbox/Screenshot_2023-06-18-06-12-55_5605.png)

Given binary file that turns out aarch64 binary, because this is my first time reversing another architecture i need to set up qemu and download aarch64 glibc, but then i ran out to the first error. 

```bash
nahamcon/rev/sandbox via 🐍 v3.11.3 
❯ ./the-sandbox 
qemu-aarch64-static: Could not open '/lib/ld-linux-aarch64.so.1': No such file or directory
```
The linker isn't there??, after searching through my filesystem i realized my aarch64 glibc was on another folder so to resolve this we simply have to specify the glibc path with -L flag.

```bash
nahamcon/rev/sandbox via 🐍 v3.11.3 
❯ qemu-aarch64 -L /usr/aarch64-linux-gnu the-sandbox 
Enter your key: a
Enter your password: a
Try again!           
```

Nice now i can run the binary with qemu-aarch64 because i don't know how to specify glibc path in qemu-static (can we?).

We can run the binary but we still have to reverse it to get the correct key and password i use ghidra mainly and sometimes uses this online tool for decompiler comparation [Tools](dogbolt.org/)

### Reversing on Ghidra

because the binary is stripped there's no function name so we can't easly search for main, to get to main first we go to entry point and look at the first parameter.

![main]()

we get our main here and it's calling some function we don't know yet.


