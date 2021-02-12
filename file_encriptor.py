import argparse
import sys
import secrets
import time
import os.path
import getpass
import bcrypt

from sage.all import ZZ, random_prime, next_prime, inverse_mod, gcd
from getpass import getpass
from math import ceil, floor, log

from string import punctuation


BASE = 256  # each char has one byte
ENCRIPTED_EXTENSION = ".parsa"
KEYFILE_EXTENSION = ".pub"

HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE - PARSA ========\n"
TAIL_KEYFILE = "========= END PUBLIC KEYFILE - PARSA =========\n"


def safe_prime_bm(bit_length, count_primes):
    start = time.time()
    bm_bitlength = 512

    safe_prime(bm_bitlength)

    diff = time.time() - start
    estimate = round(diff * 2**(bit_length // bm_bitlength) * count_primes * 8)

    print(f"[*] Estimation to create {count_primes} safe primes: {str(estimate)}s.")


def safe_prime(bit_length):
    start = time.time()
    while True:
        p = random_prime(2 ** bit_length, False, 2 ** (bit_length-1))
        if ZZ((p - 1) / 2).is_prime():
            return int(p)


def init_keyfile(name, password=None, n_len=2048, hash_rounds=16):
    print(f"[*] Create keyfile with {n_len} bits and {hash_rounds} hash rounds.")

    keyfile_out = name + KEYFILE_EXTENSION

    if os.path.isfile(keyfile_out):
        raise FileExistsError("Keyfile " + keyfile_out + " already exists.")

    # test if in debug mode
    if password: 
        assert n_len >= 32, "[!] Length of n has to be at least 32 bit, functionality wise."
    else:
        assert n_len >= 2048, "[!] Length of n has to be at least 2048 bit, security wise."

    assert log(n_len,2).is_integer(), "[!] Length of n must be power of 2 (2048, 4096, ...)."

    delta = 5 + secrets.randbelow(10)
    p_length_bit = n_len // 2 + delta
    q_length_bit = n_len - p_length_bit + 1

    safe_prime_bm(n_len//2, 2)
    p = safe_prime(p_length_bit)
    q = safe_prime(q_length_bit)

    n = p*q
    phi = (p-1)*(q-1)

    debug = True
    if password is None:
        debug = False

        while True:
            password = getpass("[*] Please enter the password to use for the encription: ")
            password_check = getpass("[*] Please re-enter the password: ")

            check_password_strength(password)

            if password_check == password:
                break
            else:
                print("[!] Passwords did not match, please try again.")

    salt = create_salt(hash_rounds)
    d_in, bit_diff  = get_num_from_password(password, n_len, salt)

    while True:
        
        # create d near at phi, regardless where d_in is
        # 0 ... d_in ..................... d ........ phi
        # 0 .............................. d . d_in . phi
        offset_bit_size = 16
        random_offset = secrets.randbelow(2**(offset_bit_size - 1))

        d = next_prime(int(d_in * 2**(bit_diff-offset_bit_size) + random_offset))

        if gcd(d, phi) == 1:
            e = inverse_mod(d, phi)
            diff = d - d_in

            # enforce big e's (at least as big as d)
            if e > n_len - offset_bit_size:
                print("[*] Found valid d and e")
                break

    assert e * d % phi == 1, "[!] e * d != 1 (mod phi(n))"

    del p
    del q
    del phi

    quotient = diff // d_in
    remainder = diff % d_in

    keyfile = open(keyfile_out, "w")
    keyfile.write(HEADER_KEYFILE)
    keyfile.write(str(n) + ":" + str(n_len) + "\n")
    keyfile.write(str(e) + "\n")
    keyfile.write(str(salt) + ":" + str(quotient) + ":" + str(remainder) + "\n")
    keyfile.write(TAIL_KEYFILE)
    keyfile.close()

    # i.e. in Test / Debug mode
    if debug:
        print("[#] n:    " + str(n))
        print("[#] e:    " + str(e))
        print("[#] d:    " + str(d))
        print("[#] d_in: " + str(d_in))
        print("[#] diff: " + str(diff))

        return n, e, d, d_in


def check_password_strength(password):
    if len(password) < 10:
        print("[!] Password has to be at least 10 characters long.")
        return False

    if not any(char.isdigit() for char in password):
        print("[!] Password has to contain at least one number.")
        return False

    if not any(char.isupper() for char in password):
        print("[!] Password has to contain at least one uppercase character.")
        return False

    if not any(char.islower() for char in password):
        print("[!] Password has to contain at least one lowercase character.")
        return False

    if not any(char in punctuation for char in password):
        print("[!] Password has to contain at least one special character.")
        return False

    return True


def encript(filename, keyfile):
    outfile = filename + ENCRIPTED_EXTENSION

    if os.path.isfile(outfile):
        raise FileExistsError("Encripted outfile " + outfile + " already exists.")

    k = open(keyfile, "r")
    n, e, _ = k.readlines()[1:-1]
    k.close()

    n, n_len = n.split(":")
    n = int(n)
    n_len = int(n_len.strip())

    e = int(e.strip())

    f = open(filename, "r")
    data = f.readlines()
    f.close()

    data = "".join(data)
    m = string_to_hex_nums(data, n_len)
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

    n, n_len = n.split(":")
    n = int(n)
    n_len = int(n_len.strip())

    if not password:
        password = getpass("[*] Please enter your password you used for the encription: ")

    salt, quotient, remainder = diff.split(":")
    d, _ = get_num_from_password(password, n_len, salt)
    d += int(quotient) * d + int(remainder)

    f = open(filename, "r")
    data = f.readlines()
    f.close()

    plain = []
    for c in data:
        c = int(c.strip())

        # c^d mod n
        m = pow(c, d, n)
        plain.append(hex(m)[2:])
    
    plain = hex_nums_to_string(plain, n_len)

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

    as_hex = string.encode(encoding='ascii').hex()

    hex_nums = []
    for i in range(blocks):
        hex_nums.append(as_hex[i*block_size:(i+1)*block_size])

    # padding
    diff = block_size - len(hex_nums[-1])
    hex_nums[-1] += "0" * diff

    return hex_nums


def hex_nums_to_string(hex_nums, n_len):
    if not isinstance(hex_nums, list) or not isinstance(hex_nums[0], str):
        raise Exception("Only list of hex nums allowed: ", hex_nums)
    
    # reattach leading 0s
    block_size = n_len // 4

    for i in range(len(hex_nums)):
        diff = block_size - len(hex_nums[i])
        hex_nums[i] = "0" * diff + hex_nums[i]

    # remove padding (50 50 00 -> 50 50)
    i = len(hex_nums[-1]) - 1
    while hex_nums[-1][i] == hex_nums[-1][i-1] == "0" and i > 2:
        i -= 2  # -2 because ascii encoding uses 2 hex chars per char -> ascii 0 == hex 00

    hex_nums[-1] = hex_nums[-1][:i+1]

    recreated = "".join(hex_nums)
    s = bytes.fromhex(recreated).decode(encoding='ascii')

    return s


def create_salt(rounds):
    return bcrypt.gensalt(rounds).decode()


def get_num_from_password(password, n_len, salt):
    hashed = bcrypt.hashpw(password.encode(), salt.encode()).decode()
    _, _, rounds, hashed = hashed.split("$")

    d_in = int.from_bytes(hashed.encode(), "big")
    bit_diff = n_len - d_in.bit_length()

    # if d_in is bigger than n -> rightshift so it fits
    if bit_diff < 0:
        d_in = d_in >> -bit_diff
        bit_diff = 0

    # still bigger than n -> shift once more
    if d_in > 2**n_len:
        d_in = d_in >> 1

    # only print this if not testing exhaustively (i.e. rounds == 16)
    if rounds == 16:
        print("[*] Password hashed and transformed to number < n")

    return d_in, bit_diff


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
