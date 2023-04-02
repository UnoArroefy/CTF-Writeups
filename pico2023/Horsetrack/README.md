# Horsetrack - PWN

## recon

This challenge give us patched binary, its libc, and linker, looking at the libc given first thing i want to check is the libc version that this binary patched
with, by typing `string libc.so.6 | grep GNU` we know what the libc version is using.

