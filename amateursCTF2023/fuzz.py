print("----\'\'.__dir__()---")

for code in "".__dir__():
    if not any([i in code for i in "\lite0123456789"]):
        print(code)

print("-----builtins------")

for code in dir(__builtins__):
    if not any([i in code for i in "\lite0123456789"]):
        print(code)