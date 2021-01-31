import argparse
import sys
import secrets
import time
import os.path
import getpass

from sage.all import ZZ, random_prime, next_prime, inverse_mod, gcd


BASE = 256  # each char has one byte
EXTENSION = ".parsa"

HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE PASSWORD RSA ========\n"
TAIL_KEYFILE = "========= END PUBLIC KEYFILE PASSWORD RSA =========\n"


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


def init_keyfile(name, password=None):

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

    print(p)
    print(q)

    del p
    del q

    if password is None:
        d = getpass.getpass(prompt="Please enter the password to use for the encription: ")
    else:
        d = password

    d = d.encode()
    d = int.from_bytes(d, "big")

    while True:
        offset = secrets.randbelow(10**6)
        d_prime = next_prime(d + offset)

        if gcd(d_prime, phi) == 1:
            e = inverse_mod(d_prime, n)
            diff = d_prime - d
            print("Found valid d and e")
            break

    print(n)
    print(e)
    print(d)
    print(diff)

    keyfile = open(name, "w")
    keyfile.write(HEADER_KEYFILE)
    keyfile.write(n + "\n")
    keyfile.write(e + "\n")
    keyfile.write(diff + "\n")
    keyfile.write(TAIL_KEYFILE)
    keyfile.close()


def encript(filename, keyfile):
    outfile = filename + EXTENSION

    if os.path.isfile(outfile):
        raise FileExistsError("Encripted outfile " + outfile + " already exists.")

    k = open(keyfile, "r")
    n, e, _ = k.readlines()[1:-1]
    k.close()

    f = open(filename, "rb")
    data = f.readlines()
    f.close()

    m = int.from_bytes(data, "big")

    # m^e mod n
    cipher = pow(m, e, n)

    c = open(filename + EXTENSION, "wb")
    c.write(cipher)
    c.close()

    print("Successfully encripted contents of " + filename + " and saved them under " + outfile)


def decript(filename, keyfile, show_decripted, save_decripted):
    outfile = filename[:-len(EXTENSION)]

    if os.path.isfile(outfile):
        raise FileExistsError("Decripted outfile " + outfile + " already exists.")

    k = open(keyfile, "r")
    n, _, diff = k.readlines()[1:-1]
    k.close()

    d = input("Please enter your password you used for the encription: ")
    d = string_to_number(d)

    f = open(filename, "rb")
    data = f.readlines()
    f.close()

    c = int.from_bytes(data, "big")

    # c^d mod n
    plain = pow(c, d, n)
    plain = number_to_string(plain)

    print("Successfully decripted contents of " + filename + ".")
    if show_decripted:
        print("Result of decription see below.")
        print("*******************************")
        print(plain)
        print("*******************************")

    if save_decripted:
        m = open(filename + EXTENSION, "wb")
        m.write(plain)
        print("Contents saved in " + outfile + ".")


def string_to_number(string):
    if not isinstance(string, str):
        raise Exception("Only strings allowed: ", string)

    return int(string, base=BASE)


def number_to_string(num):
    if not isinstance(num, int):
        raise Exception("Only integers allowed: ", num)

    return hex(num)[2:]


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='parsa - PAssword RSA.\n'
                    'Encript and Decript contents of files via RSA algorithm.\n'
                    'The private key is a password of your choosing.')

    parser.add_argument("-i", "--init",
                        help="Init a keyfile, name of keyfile.",
                        type=str)

    parser.add_argument("-k", "--keyfile",
                        help="Encription and Decription mode, name of keyfile",
                        type=str)

    parser.add_argument("-e", "--encript",
                        help="Encription mode, name of file to encript.",
                        type=str)

    parser.add_argument("-d", "--decript",
                        help="Decription mode, name of file to decript.",
                        type=str)

    parser.add_argument("-v", "--verbose",
                        help="Decription mode, print decripted file.")

    parser.add_argument("-s", "--save",
                        help="Decription mode, save decripted file.")

    return parser.parse_args(argv)


if __name__ == "__main__":
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
    private = (n,password)
    """

    args = parse_args(sys.argv[1:])
    print(args)

    if args.init:
        keyfile_name = args.init
        print("Init keyfile: " + keyfile_name)
        init_keyfile(keyfile_name)

    elif args.keyfile:
        keyfile_name = args.keyfile

        if args.encript:
            file = args.encript
            print("Encript: " + file)

            encript(file, keyfile_name)

        elif args.decript:
            file = args.decript
            print("Decript: " + args.decript)

            decript(file, keyfile_name, args.verbose, args.save)
