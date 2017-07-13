ary = [1376627084, 1208859320, 1482862807, 1326295511, 1181531558, 2003814564]
s = ""
for i in ary:
    s += hex(i ^ 170780919)[2:].decode('hex')[::-1]

print s
#AIS3{A XOR B XOR A EQUALS B}
