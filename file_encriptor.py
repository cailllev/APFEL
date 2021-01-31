import argparse
import sys
import secrets
import time
import os.path

from sage.all import ZZ, random_prime, next_prime, inverse_mod, gcd


header_keyfile = "======== BEGIN PUBLIC KEYFILE PASSWORD RSA ========\n"
tail_keyfile = "========= END PUBLIC KEYFILE PASSWORD RSA =========\n"


def safe_prime(bit_length):
    start = time.time()
    benchmark_bitlength = 10
    while True:
        p = random_prime(2 ^ benchmark_bitlength - 1, False, 2 ^ benchmark_bitlength)
        if ZZ((p - 1) / 2).is_prime():
            break
    diff = time.time() - start
    estimate = diff * 2.718**(bit_length / benchmark_bitlength)
    print("Creating safe primes, estimated time: " + str(estimate))

    while True:
        p = random_prime(2 ^ bit_length - 1, False, 2 ^ bit_length)
        if ZZ((p - 1) / 2).is_prime():
            return p


def init_keyfile(name):

    if os.path.isfile(name):
        raise FileExistsError("Keyfile " + name + " already exists.")

    n_length_bit = 2048  # 136 bit security

    delta = 10 + secrets.randbelow(20)
    p_length_bit = n_length_bit >> 1 + delta
    q_length_bit = n_length_bit - p_length_bit - 1

    p = safe_prime(p_length_bit)
    q = safe_prime(q_length_bit)

    n = p*q
    phi = (p-1)*(q-1)

    """
    normal rsa:
    1. choose e
    2. d is e's mod_inv in phi
    public = (n,e)
    private = (n,d)
    
    
    "password" rsa:
    1. enter password -> d
    2. d_prime = next_prime(d + random)
    3. diff = d_prime - d
    4. e is d's mod_inv in phi, if no inv -> go to 2.
    public = (n,e,diff)
    private = "only a password"
    """

    d = input("Please enter your password used for the encription: ")

    while True:
        offset = secrets.randbelow(10**6)
        d_prime = next_prime(d + offset)

        if gcd(d_prime, phi) == 1:
            e = inverse_mod(d_prime, n)
            diff = d_prime - d
            print("Found valid d and e")
            break

    print(p)
    print(q)
    print(n)
    print(e)
    print(d)
    print(diff)

    keyfile = open(name, "wb")
    keyfile.write(header_keyfile)
    keyfile.write(n + b"\n")
    keyfile.write(e + b"\n")
    keyfile.write(diff + b"\n")
    keyfile.write(tail_keyfile)


def encript(filename):
    pass


def decript(filename):
    pass


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Encript and Decript files via RSA algorithm. '
                    'The private key is a password of your choosing.')

    parser.add_argument("-i", "--init",
                        help="Init a keyfile, name of keyfile.",
                        type=str)

    parser.add_argument("-e", "--encript",
                        help="Encription mode, name of file to encript.",
                        type=str)

    parser.add_argument("-d", "--decript",
                        help="Decription mode, name of file to decript.",
                        type=str)

    parser.add_argument("-v", "--verbose",
                        help="Decription mode, print decripted file.")

    parser.add_argument("-o", "--out",
                        help="Decription mode, name to save decripted file with.",
                        type=str)

    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    print(args)

    if args.init:
        keyfile_name = args.init
        print("Init keyfile: " + keyfile_name)
        init_keyfile(keyfile_name)

    elif args.encript:
        file = args.encript
        print("Encript: " + file)

        encript(file)

    elif args.decript:
        file = args.decript
        print("Decript: " + args.decript)

        decript(file)
