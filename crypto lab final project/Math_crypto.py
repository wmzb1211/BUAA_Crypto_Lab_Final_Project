import math
import random

def Egcd(a, b):
    """
    calculate gcd(a, b)
    :param a: int
    :param b: int
    :return: ans -> int
    """
    if type(a) != int or type(b) != int:
        raise ValueError("a and b must be integers.")
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = Egcd(b, a % b)
        x, y = y, x - (a // b) * y
        if x < 0:  # 如果x为负数，则加上一个b
            x += b
            y -= a
        return x, y, q

def gcd(a, b):
    x, y, q = Egcd(a, b)
    return q

def invmod(x, p):
    temp, _, _ = Egcd(x, p)
    return temp % p

def is_prime(n):
    """
    check if N is a prime or not.
    use Miller Rabin algorithm.
    :param N: int
    :return: bool
    """
    if n < 2 or type(n) != int:
        raise ValueError("n must be a positive integer.")
    k = 30
    if n == 2:
        return True
    if n == 1 or n & 1 == 0:
        return False
    else:
        s = 0
        d = n - 1
        while d & 1 == 0:
            s += 1
            d = d // 2
        for i in range(k):
            a = random.randint(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            else:
                for j in range(s - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
        return True

def miller_rabin(n):
    return is_prime(n)

def get_prime(n):
    if n < 2 or type(n) != int:
        raise ValueError("n must be a positive integer.")
    while True:
        temp = random.randint(2 ** (n - 1), 2 ** n)
        if is_prime(temp):
            return temp

def get_BigPrime(N):
    """
    generate a prime about n bit
    :param n:
    :return: a prime
    """
    if N < 2 or type(N) != int:
        raise ValueError("n must be a positive integer.")
    x = (1 << N) + 1
    while 1:
        if is_prime(x):
            break
        x += 2
    return x

def BigInt2Str(n):
    temp = hex(n)[2:]
    if len(temp) & 1 == 1:
        temp = '0' + temp
    return bytes.fromhex(temp).decode()

def Str2BigInt(s):
    return int(s.encode().hex(), 16)

def fastpower(a, b, c):
    """
    calculate a ^ b % c
    :param a: int
    :param b: int
    :param c: int
    :return: ans -> int
    """
    if type(a) != int or type(b) != int or type(c) != int:
        raise ValueError("a, b, c must be integers.")
    ans = 1
    while b:
        if b & 1:
            ans = (ans * a) % c
        a = (a * a) % c
        b >>= 1
    return ans





















