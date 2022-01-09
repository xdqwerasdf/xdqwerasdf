a = [7, 3, 1] * 2
b = [1,1,1,1,1,6]
print sum([a[i] * b[i] for i in range(6)]) % 10