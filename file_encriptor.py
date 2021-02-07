import argparse
import sys
import secrets
import time
import os.path
import getpass

from sage.all import ZZ, random_prime, next_prime, inverse_mod, gcd
from getpass import getpass
from math import ceil, floor, log


BASE = 256  # each char has one byte
ENCRIPTED_EXTENSION = ".parsa"
KEYFILE_EXTENSION = ".pub"

HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE - PARSA ========\n"
TAIL_KEYFILE = "========= END PUBLIC KEYFILE - PARSA =========\n"


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

    # testing purposes
    if n_len:
        assert n_len >= 64, "[!] Length of n has to be at least 128 bit. Not security, but functionality wise."
        assert log(n_len,2).is_integer(), "[!] Length of n must be power of 2."
        n_length_bit = n_len
    else:
        n_length_bit = 2048  # 136 bit security

    delta = 5 + secrets.randbelow(10)
    p_length_bit = n_length_bit // 2 + delta
    q_length_bit = n_length_bit - p_length_bit + 1

    safe_prime_bm(n_length_bit//2, 2)
    p = safe_prime(p_length_bit)
    q = safe_prime(q_length_bit)

    n = p*q
    phi = (p-1)*(q-1)

    if password is None:
        d_in = getpass("[*] Please enter the password to use for the encription: ")
    else:
        d_in = password

    d_in = string_to_hex_nums(d_in, n_length_bit)
    assert len(d_in) == 1, f"Bit length of password must not be bigger than {n_length_bit}, {d_in}"

    d_in = d_in[0]
    bit_diff = n_length_bit - (len(d_in) * 4)

    d_in = int(d_in, 16)

    while True:
        
        # create d near at phi
        # 0 ... d_in ......................... d ... phi
        offset_bit_size = 8
        random_offset = secrets.randbelow(2**(offset_bit_size - 1))

        d = d_in * 2**(bit_diff-offset_bit_size) + random_offset

        if gcd(d, phi) == 1:
            e = inverse_mod(d, phi)
            diff = d - d_in
            print("[*] Found valid d and e")
            break

    assert e * d % phi == 1, "[!] e * d != 1 (mod phi(n))"

    del p
    del q
    del phi

    quotient, remainder = divmod(diff, d_in)

    keyfile = open(keyfile_out, "w")
    keyfile.write(HEADER_KEYFILE)
    keyfile.write(str(n) + "\n")
    keyfile.write(str(e) + "\n")
    keyfile.write(str(quotient) + ":" + str(remainder) + "\n")
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
    m = string_to_hex_nums(data, n.bit_length())
    cipher = []

    # m^e mod n
    for num in m:
        num = int(num, 16)  # convert from hex to decimal number
        cipher.append(str(pow(num, e, n)) + "\n")

    cipher = "".join(cipher)

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

    d = int(string_to_hex_nums(password, n.bit_length())[0], 16)
    quotient, remainder = diff.split(":")
    d += int(quotient) * d + int(remainder)

    f = open(filename, "r")
    data = f.readlines()
    f.close()

    plain = []
    for c in data:
        c = int(c)

        # c^d mod n
        m = pow(c, d, n)
        plain.append(hex(m)[2:])
    
    plain = hex_nums_to_string(plain)

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


def string_to_hex_nums(string, n_len):
    if not isinstance(string, str):
        raise Exception("Only string allowed: ", string)

    block_size = n_len // 4  # n == 128 -> 32 hex chars per block 
    blocks = ceil((len(string) * 2) / block_size)

    as_hex = string.encode().hex()

    hex_nums = []
    for i in range(blocks):
        hex_nums.append(as_hex[i*block_size:(i+1)*block_size])

    #diff = block_size - len(hex_nums[-1])  # 32 - 10 => 22
    #padding_char = hex(diff)[2:]
    #hex_nums[-1] = hex_nums[-1] + [padding_char] * diff // 2

    return hex_nums


def hex_nums_to_string(hex_nums):
    if not isinstance(hex_nums, list) or not isinstance(hex_nums[0], str):
        raise Exception("Only list of hex nums allowed: ", hex_nums)

    recreated = "".join(hex_nums)
    s = bytes.fromhex(recreated).decode()

    return s


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
