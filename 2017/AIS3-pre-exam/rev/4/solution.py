with open("dumpBin", 'r') as f:
    matrix_hex = f.read()

chunk = len(matrix_hex)
chunk_size = 8
matrix = [matrix_hex[i:i+chunk_size][::-1].encode('hex')
          for i in range(0, chunk, chunk_size)]
matrix = [int(i, 16) for i in matrix]

N = 0x400
node = [[0 for i in range(N)] for j in range(N)]
for i in xrange(N * 2 - 1):
    if i < N:
        left = i
        right = 0
    else:
        left = N - 1
        right = i - N + 1

    while left in range(N) and right in range(N):
        findMin = []
        if right - 1 in range(N):
            findMin.append(node[left][right - 1])
        if left - 1 in range(N):
            findMin.append(node[left - 1][right])

        node[left][right] = (
            matrix[(left << 10) + right] +
            min([0] if not findMin else findMin))

        left -= 1
        right += 1

print node[N-1][N-1]
# 2499910047264
