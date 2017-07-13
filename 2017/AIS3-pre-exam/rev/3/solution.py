import claripy
import hashlib


def findAns(ind):
    possible = s.eval(x[ind], 17, extra_constraints=ext)
    if ind > 15:
        ruleAry.append(ext[:])
        print 'add new ext'
        return

    for i in possible:
        ext.append(x[ind] == i)
        findAns(ind + 1)
        ext.pop()

ruleAry = []
s = claripy.Solver()
x = []
ans = [17, 0, 0, 10, 0, 0, 0, 6, 0, 18, 1, 0,
       0, 0, 0, 0, 0, 0, 21, 2, 0, 16, 0, 0, 0]
for i in xrange(17):
    x.append(claripy.BVS(str(i), 8))
    for j in ans:
        s.add(x[i] != j)
    s.add(claripy.ULE(x[i], 25))

# add rule !=
for i, vali in enumerate(x):
    for j, valj in enumerate(x):
        if(i != j):
            s.add(vali != valj)

# add x to ans
ind = 0
for i, val in enumerate(ans):
    if val == 0:
        ans[i] = x[ind]
        ind += 1

# total(row), total(col) == 65
rule = [0 for i in range(10)]
for i in xrange(5):
    for j in xrange(5):
        rule[i] += ans[i * 5 + j]
        rule[5 + j] += ans[i * 5 + j]

for i in rule:
    s.add(i == 65)

s.add((x[4] - x[11] + x[16] - x[5]+0x15 - x[13] + 0x11 - x[2]) == 0)

ext = []
findAns(0)
for i in ruleAry:
    # print i
    curAns = []
    for j in x:
        curAns.append(s.eval(j, 1, extra_constraints=i)[0])

    ind = 0
    curAnsAry = ans[:]
    for j, val in enumerate(curAnsAry):
        if not isinstance(val, int):
            curAnsAry[j] = curAns[ind]
            ind += 1

    curAnsAryChr = [chr(k) for k in curAnsAry]
    ha = hashlib.sha256(''.join(curAnsAryChr)).hexdigest()
    print ha
    if ha == 'cf252238dc5077b46d45cf941d09d925' \
             'd141cc55bb7a8f96a8648b594af3a6a5':
        data = curAnsAry
        break

f = [0x70, 0x7E, 0x77, 0x39, 0x70,
     0x51, 0x5A, 0x65, 0x6D, 0x7C,
     0x5E, 0x74, 0x62, 0x7F, 0x6F,
     0x6D, 0x51, 0x21, 0x6D, 0x37,
     0x2E, 0x31, 0x68, 0x7D, 0x74]

s = ''
for i, val in enumerate(data):
    s += chr(val ^ f[i])

print s
