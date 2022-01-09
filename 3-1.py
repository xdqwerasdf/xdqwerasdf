from Crypto.Util.number import inverse
from random import randint

def int2str(a):
    s = ''
    for i in range(8):
        s += chr(a % 256)
        a >>= 8

    s = s[::-1]
    a >>= 352

    return (a & ((1 << 32) - 1)), s


def check(a):
    a >>= 64
    a = a & ((1 << 352) - 1)
    if a == 0:
        return 1
    else:
        return 0


def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)


def exgcd(a, b):
    if b == 0:
        return 1, 0
    x, y = exgcd(b, a % b)
    return y, x - a // b * y


def common_mod(n, e1, c1, e2, c2):
    # 共模攻击
    x, y = exgcd(e1, e2)
    return pow(c1, x, n) * pow(c2, y, n) % n


def common_factor(n1, e1, c1, n2, e2, c2):
    # 公因数攻击
    p = gcd(n1, n2)
    q1 = n1 // p
    q2 = n2 // p
    phi1 = (p - 1) * (q1 - 1)
    phi2 = (p - 1) * (q2 - 1)
    d1 = inverse(e1, phi1)
    d2 = inverse(e2, phi2)
    return pow(c1, d1, n1), pow(c2, d2, n2)


def crt(a, m):
    M = 1
    for i in m:
        M *= i

    res = 0
    for i in range(len(m)):
        res = (res + a[i] * M // m[i] * inverse(M // m[i], m[i])) % M

    return res


def broadcast(a, m, e):
    c = crt(a, m)
    l, r = 1, c
    while l + 1 < r:
        md = (l + r) // 2
        if md ** e < c:
            l = md
        else:
            r = md

    if l ** e == c:
        return l
    if r ** e == c:
        return r

    return 0


def p_1(n, e, c, b):
    # p-1 分解
    k = 1
    for i in range(b):
        k *= i + 1

    p = gcd(pow(2, k, n) - 1, n)
    if p == 1 or p == n:
        return 0
    q = n // p
    if p * q != n:
        return 0
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return pow(c, d, n)

    return 0


def main():
    n = []
    e = []
    c = []

    for i in range(21):
        f = open('./data/Frame' + str(i))
        s = f.read()
        n.append(int(s[:256], 16))
        e.append(int(s[256:512], 16))
        c.append(int(s[512:], 16))

    m = [0 for i in range(21)]

    # 共模攻击
    print("Common mod:")
    for i in range(21):
        for j in range(i):
            if n[i] == n[j]:
                # print(i, j, gcd(e[i], e[j]))
                m[i] = common_mod(n[i], e[i], c[i], e[j], c[j])
                m[j] = m[i]
                print(i, j, ":", int2str(m[i]))

    # 公因数攻击
    print("Common factor:")
    for i in range(21):
        for j in range(i):
            if gcd(n[i], n[j]) > 1 and n[i] != n[j]:
                m[i], m[j] = common_factor(n[i], e[i], c[i], n[j], e[j], c[j])
                print(i, ":", int2str(m[i]))
                print(j, ":", int2str(m[j]))

    # 广播攻击
    print("Broadcast:")
    id = [3, 8, 12, 16, 20]
    temp = broadcast([c[i] for i in id], [n[i] for i in id], 5)
    for i in id:
        m[i] = temp
    print(int2str(temp))

    # p-1 分解
    print("P-1:")
    for i in range(1, 21):
        if m[i] > 0:
            continue
        temp = p_1(n[i], e[i], c[i], 10000)
        if temp > 0:
            print(i, ":", int2str(temp))


main()