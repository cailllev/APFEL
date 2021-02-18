from sage.all import Primes

def my_miller_rabin(n):
    r = 0
    s =  n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    a = 2  # base 2 needed
    x = pow(a, s, n)
    if x == 1 or x == n - 1:
        pass  # # is strong probably prime (fermat test)

    else:
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break  # is strong probably prime

        else:
            return False
    return True


def jacobi_symbol(a, n):
    """
    O(log(a)*log(n))
    https://www.johndcook.com/blog/2019/02/12/computing-jacobi-symbols/
    """

    t = 1
    while a != 0:
        while a % 2 == 0:
            a /= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == n % 4 == 3:
            t = -t
        a %= n
    if n == 1:
        return t
    else:
        return 0


def is_lucas_prime(n, d, p, q):
    """
    https://stackoverflow.com/questions/15013813/need-help-implementing-a-lucas-pseudoprimality-test#answer-15054189
    """

    u = 0
    v = 2
    u2 = 1
    v2 = p
    q2 = 2*q

    bits = []
    t = (n + 1) // 2
    while t > 0:
        bits.append(t % 2)
        t = t // 2

    h = 0
    while h < len(bits):
        u2 = (u2 * v2) % n

        # v2 = (v2 * v2 - q2) % n
        v2 = pow(v2, 2, n)  
        v2 = v2 - q2

        if v2 < 0:
            v2 += n

        if bits[h] == 1:
            uold = u
            u = u2 * v + u * v2
            u = u if u % 2 == 0 else u + n
            u = (u // 2) % n
            v = (v2 * v) + (u2 * uold * d)
            v = v if v % 2 == 0 else v + n
            v = (v // 2) % n

        if h < len(bits) - 1:
            q = pow(q, 2, n)
            q2 = 2*q
        h = h + 1

    return u == 0


def my_is_prime(n):
    """
    https://en.wikipedia.org/wiki/Baillie%E2%80%93PSW_primality_test#The_test
    1. Optionally, perform trial division to check if n is divisible by a small prime number less than some convenient limit.
    2. Perform a base 2 strong probable prime test. If n is not a strong probable prime base 2, then n is composite; quit.
    3. Find the first D in the sequence 5, −7, 9, −11, 13, −15, ... for which the Jacobi symbol (D/n) is −1. Set P = 1 and Q = (1 − D) / 4.
    4. Perform a strong Lucas probable prime test on n using parameters D, P, and Q. If n is not a strong Lucas probable prime, then n is composite. Otherwise, n is almost certainly prime.
    """

    # 1.
    P = Primes()
    for i in range(1000):
        if n % P.unrank(i) == 0:
            return False

    # 2.
    if not my_miller_rabin(n):
        return False

    # 3.
    P = 1
    Q = 0
    D = 5
    sign = 1

    while True:
        if jacobi_symbol(D, n) == -1:
            Q = (1-D) / 4
            break

        sign *= -1
        D = (D + 2) * sign 

    # 4.
    return is_lucas_prime(n, D, P, Q)


def my_pow(x, e, m):
    """
    x**13 = x**1 * x**4 * x**8 = x<<0 * x<<2 * x<<3 
    => x<<0, x<<1, x<<2, ... = current
    res = res * current, if ith bit set
    """

    res = 1
    current = x

    for i in range(e.bit_length()):

        # test if ith bit is set in e
        if e & (1<<i):  
            res *= current
            res %= m

        current **= 2
        current %= m

    return res