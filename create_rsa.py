import math
import random

from create_primes import generate_prime
from utility import string_to_number
from utility import keyfile_name
from utility import java_next_prime


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m


n_length_bit = 2048  # 136 bit security

private_key = input("Please enter your password: ")

delta = random.randint(17, 37)
p_length_bit = int(n_length_bit / 2 + delta)
q_length_bit = n_length_bit - p_length_bit

d_not_found = True
loops = 0

# (n, d) private    --> d is nextPrime(sha256(password))
# (n, e) public     --> e is created according to d and phi_n

while d_not_found:
    loops += 1
    p = generate_prime(p_length_bit)
    q = generate_prime(q_length_bit)

    n = p * q
    phi_n = (p-1)*(q-1)
    # private_key = sha256(private_key)
    d_prop = string_to_number(private_key)

    d = int(java_next_prime(d_prop))
    diff = d - d_prop

    if math.gcd(phi_n, d) == 1:  # found a valid configuration for p and q regarding fixed d_prop
        d_not_found = False
        e = modinv(d, phi_n)

        if e is None or ((e*d) % phi_n) != 1:
            continue

        keyfile = open(keyfile_name(), "w")
        keyfile.write(str(n) + "\n")
        keyfile.write(str(e) + "\n")
        keyfile.write(str(diff) + "\n")
        keyfile.close()
        break

    print("Tried " + str(loops) + " configurations")


print("n, e and d created, n and e (and diff to prime) written to " + keyfile_name())
