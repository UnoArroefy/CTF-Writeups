#!/usr/local/bin/python
from flag import flag

for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if any([i in code for i in "\lite0123456789"]):
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)

# solution : 
# any=''.__mod__
# print(_)
# solution 2 : vars()[_]
# amateursCTF{sh0uld'v3_r3strict3D_p4r3nTh3ticaLs_1nst3aD}