import argparse
import sys
import secrets
import time
import os.path
import getpass

from sage.all import ZZ, random_prime, next_prime, inverse_mod, gcd
from getpass import getpass


BASE = 256  # each char has one byte
ENCRIPTED_EXTENSION = ".parsa"
KEYFILE_EXTENSION = ".pub"

HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE PASSWORD RSA ========\n"
TAIL_KEYFILE = "========= END PUBLIC KEYFILE PASSWORD RSA =========\n"


def safe_prime_bm(bit_length, count_primes):
    start = time.time()
    bm_bitlength = 200

    while True:
        p = random_prime(2 ** bm_bitlength, False, 2 ** (bm_bitlength - 1))
        if ZZ((p - 1) / 2).is_prime():
            break

    diff = time.time() - start
    estimate = diff * 2**(bit_length // bm_bitlength) * count_primes
    variance = 4
    est_min = round(estimate / variance)
    est_max = round(estimate * variance)

    print(f"[*] Estimation to create safe primes between: {str(est_min)}s and {str(est_max)}s")


def safe_prime(bit_length):
    start = time.time()
    while True:
        p = random_prime(2 ** bit_length, False, 2 ** (bit_length-1))
        if ZZ((p - 1) / 2).is_prime():
            print("[*] Actual used time: " + str(round(time.time() - start)) + "s")
            return p


def init_keyfile(name, password=None, n_len=2048):
    keyfile_out = name + KEYFILE_EXTENSION

    if os.path.isfile(keyfile_out):
        raise FileExistsError("Keyfile " + keyfile_out + " already exists.")

    if n_len:
        n_length_bit = n_len  # testing purposes
    else:
        n_length_bit = 2048  # 136 bit security

    delta = 10 + secrets.randbelow(20)
    p_length_bit = n_length_bit // 2 + delta
    q_length_bit = n_length_bit - p_length_bit - 1

    safe_prime_bm(n_length_bit//2, 2)
    p = safe_prime(p_length_bit)
    q = safe_prime(q_length_bit)

    n = p*q
    phi = (p-1)*(q-1)

    if password is None:
        d_in = getpass("[*] Please enter the password to use for the encription: ")
    else:
        d_in = password

    d_in = string_to_number(d_in)

    while True:
        offset = secrets.randbelow(10**6)
        d = next_prime(d_in + offset)

        if gcd(d, phi) == 1:
            e = inverse_mod(d, n)
            diff = d - d_in
            print("[*] Found valid d and e")
            break

    assert e * d % n == 1, "[!] e * d != 1 (mod n)"

    del p
    del q
    del phi

    keyfile = open(keyfile_out, "w")
    keyfile.write(HEADER_KEYFILE)
    keyfile.write(str(n) + "\n")
    keyfile.write(str(e) + "\n")
    keyfile.write(str(diff) + "\n")
    keyfile.write(TAIL_KEYFILE)
    keyfile.close()

    # i.e. in Test / Debug mode
    if password:
        print("[#] n:    " + str(n))
        print("[#] e:    " + str(e))
        print("[#] d:    " + str(d))
        print("[#] d_in: " + str(d_in))
        print("[#] diff: " + str(diff))

        return n, e, d


def encript(filename, keyfile):
    outfile = filename + ENCRIPTED_EXTENSION

    if os.path.isfile(outfile):
        raise FileExistsError("Encripted outfile " + outfile + " already exists.")

    k = open(keyfile, "r")
    n, e, _ = k.readlines()[1:-1]
    k.close()

    n = int(n.strip())
    e = int(e.strip())

    f = open(filename, "r")
    data = f.readlines()
    f.close()

    data = "".join(data)
    m = string_to_number(data)
    print("[m]: " + str(m))


    # m^e mod n
    cipher = str(pow(m, e, n))

    c = open(outfile, "w")
    c.write(cipher)
    c.close()

    print("[*] Successfully encripted contents of " + filename + " and saved them under " + outfile)


def decript(filename, keyfile, password=None, show_decripted=False, save_decripted=False):

    k = open(keyfile, "r")
    n, _, diff = k.readlines()[1:-1]
    k.close()

    n = int(n.strip())

    if not password:
        password = getpass("[*] Please enter your password you used for the encription: ")

    d = string_to_number(password)
    d += int(diff)

    f = open(filename, "r")
    data = f.readline()
    f.close()

    c = int(data)
    print("[c]: " + str(c))

    # c^d mod n
    plain = pow(c, d, n)
    print("[d]: " + str(d))
    print("[n]: " + str(n))
    print("[m]: " + str(plain))
    plain = number_to_string(plain)

    print("[*] Successfully decripted contents of " + filename + ".")
    if show_decripted:
        print("[*] Result of decription see below.")
        print("*******************************")
        print(plain)
        print("*******************************")

    if save_decripted:
        outfile = filename[:-len(ENCRIPTED_EXTENSION)]

        if os.path.isfile(outfile):
            raise FileExistsError("[!] Decripted outfile " + outfile + " already exists.")

        m = open(outfile, "w")
        m.write(plain)
        m.close()
        print("[*] Contents saved in " + outfile + ".")


def string_to_number(string):
    if not isinstance(string, str):
        raise Exception("Only strings allowed: ", string)

    return int.from_bytes(string.encode(), "big")


def number_to_string(num):
    if not isinstance(num, int):
        raise Exception("Only integers allowed: ", num)

    l = num.bit_length() // 8 + 1

    return num.to_bytes(l, "big").decode()


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

    return parser.parse_args(argv), parser


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

    args, parser = parse_args(sys.argv[1:])

    if args.init:
        keyfile_name = args.init
        print("Init keyfile: " + keyfile_name)
        init_keyfile(keyfile_name)

    elif args.keyfile:
        keyfile_name = args.keyfile

        if args.encript:
            file = args.encript
            print("[*] Encript: " + file)

            encript(file, keyfile_name)

        elif args.decript:
            file = args.decript
            print("[*] Decript: " + args.decript)

            decript(file, keyfile_name, None, args.verbose, args.save)

        else:
            print("**************************************************************************")
            print("If a keyfile is supplied, the encription or decription flag has to be set!")
            print("**************************************************************************\n")
            parser.print_help()

    else:
        print("************************************************************")
        print("Either the init flag or the keyfile flag has to be supplied!")
        print("************************************************************\n")
        parser.print_help()
