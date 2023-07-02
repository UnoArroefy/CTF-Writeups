# Cry - Morphing Time

Elgamal encryption & decryption

``` python
def encrypt_setup(p, g, A):
    def encrypt(m):
        k = randint(2, p - 1)
        c1 = pow(g, k, p)
        c2 = pow(A, k, p)
        c2 = (m * c2) % p

        return c1, c2

    return encrypt


def decrypt_setup(a, p):
    def decrypt(c1, c2):
        m = pow(c1, a, p)
        m = pow(m, -1, p)
        m = (c2 * m) % p

        return m

    return decrypt
```

Oracle

```python
m = decrypt((c1 * c1_) % p, (c2 * c2_) % p)
```

looking at how the encryption works

c1 = g^k mod p
c2 = g^ak * m mod p

during the decryption process

c1 --> g^-ak

so when c1 * c2 mod p will return m because c1 is modular inverse of c2/m (c2 before multiplied by m)

so the oracle formula become

(g^k * c1_)^-a * g^ak * m * c2_ mod p = m

g^-ak * c1^-a * g^ak * m * c2_ mod p = m

now our goal is to find c1_ and c2_ value so that it will cancel each other (modular inverse)

we know p, g, A where A is g^a mod p, based on this value we can solve the equation with A

we have to make c1_^-a --> g^-a and c2_ --> A (g^a) those value will cancel each other so the final equation is

g^-ak * g^-a * g^ak * g^a * m mod p = m

c1_^-a = g^-a so c1_ = 2, c2_ = A

we get the msg

```
>>> long_to_bytes(4207564671745017061459002831657829961985417520046041547841180336049591837607722234018405874709347956760957)
b'uiuctf{h0m0m0rpi5sms_ar3_v3ry_fun!!11!!11!!}'
```
