auth = 'A' * 32
auth += 'ytrewq\'_'[::-1]
auth += 'sa}{poiu'[::-1]
auth += 'zlkjhgfd'[::-1]
auth += '|mnbvcx'[::-1]
print auth

input_data = 'zmu}jnd{o{f_ndo{{_hz_{ga'

test = auth.index('a')
print test
print chr(test + 63)


for j in range(3):
    flag = ''
    for i in input_data:
        ind = auth.index(i)
        flag += chr(ind + 63)

    input_data = flag

print flag

#flag{theres_three_of_em}
