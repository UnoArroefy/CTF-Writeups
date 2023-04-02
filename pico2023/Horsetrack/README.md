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

