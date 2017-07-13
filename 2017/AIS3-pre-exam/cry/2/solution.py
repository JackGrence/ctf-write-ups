import base64

def b(s):
    return base64.b64decode(s).encode('hex')

a = b('EJGM1y862AghIF0MIHM6wkLobn30SXYzl+iFmGTeIU3jzPFjtGsGJIOeTIVlTQnS')
c = b('eM6Vwh2Kb2Q38C4BdlBMMap/aPmFPqyPRO1vWjrrbYCsy7TB440CwjZOAynm4zVqp208eBUgptYQuzvgOXV9cQ==')

print base64.b64encode((a[:32] + c[32:]).decode('hex'))
