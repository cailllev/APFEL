import random


def square_and_multiply(x, k, p=None):
    """
    Square and Multiply Algorithm
    Parameters: positive integer x and integer exponent k,
                optional modulus p
    Returns: x**k or x**k mod p when p is given
    """
    b = bin(k).lstrip('0b')
    r = 1
    for i in b:
        r = r**2
        if i == '1':
            r = r * x
        if p:
            r %= p
    return r


def miller_rabin_primality_test(p, s):
    if not (p & 1):         # n is a even number and can't be prime
        return False

    p1 = p - 1
    u = 0
    r = p1                  # p-1 = 2**u * r

    while r % 2 == 0:
        r >>= 1
        u += 1

    # at this stage p-1 = 2**u * r  holds
    assert p-1 == 2**u * r

    def witness(a):
        """
        Returns: True, if there is a witness that p is not prime.
                False, when p might be prime
        """
        z = square_and_multiply(a, r, p)
        if z == 1:
            return False

        for i in range(u):
            z = square_and_multiply(a, 2**i * r, p)
            if z == p1:
                return False
        return True

    for j in range(s):
        a = random.randrange(2, p-2)
        if witness(a):
            return False

    return True


def generate_prime(n):
    """
    Generates prime numbers with bitlength n.
    Stops after the generation of k prime numbers.

    Caution: The numbers tested for primality start at
    a random place, but the tests are drawn with the integers
    following from the random start.
    """

    # follows from the prime number theorem
    # get n random bits as our first number to start test for primality
    potential_prime = random.getrandbits(n)
    max_steps = 10**9
    c = 0

    while c < max_steps:
        if miller_rabin_primality_test(potential_prime, 4):
            return potential_prime

        potential_prime += 1
        c += 1

    raise Exception("Could not find a prime with length " + n + " after " + max_steps + " steps")
