#!/usr/local/bin/python
from flag import flag


for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            print(code)
            if any([i in code for i in "lite0123456789 :< :( ): :{ }: :*\ ,-."]):
                print("invalid input")
                continue
            print(__doc__)
            exec(eval(code))
        except Exception as err:
            print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
