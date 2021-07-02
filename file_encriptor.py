import argparse
import getpass
import os.path
import sys

from getpass import getpass
from utils import *
from key import algo_parser

ENCRIPTED_EXTENSION = ".apfel"
KEYFILE_EXTENSION = ".akey"

HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE - APFEL ========\n"
TAIL_KEYFILE = "========= END PUBLIC KEYFILE - APFEL =========\n"


def init_keyfile(name, password=None):

    keyfile_out = name + KEYFILE_EXTENSION

    if os.path.isfile(keyfile_out):
        raise FileExistsError("Keyfile " + keyfile_out + " already exists.")

    if password is None:
        while True:
            password = getpass("[*] Please enter the password to use for the encription: ")

            if not check_password_strength(password):
                continue

            password_check = getpass("[*] Please re-enter the password: ")

            if password_check == password:
                break
            else:
                print("[!] Passwords did not match, please try again.")

    rsa_key = init_rsa_key(password)

    keyfile = open(keyfile_out, "w")
    keyfile.write(HEADER_KEYFILE)
    keyfile.write(rsa_key)
    keyfile.write(TAIL_KEYFILE)
    keyfile.close()


def encrypt(filename, keyfile, algorithm):
    outfile = filename + ENCRIPTED_EXTENSION

    if os.path.isfile(outfile):
        raise FileExistsError(f"[!] Encripted outfile {outfile} already exists.")

    with open(keyfile, "r") as k:
        keys = k.readlines()[1:-1]

    for key in keys:
        if algorithm in key:
            break
    else:
        raise FileExistsError(f"[!] Chosen algorithm {algorithm} does not have any keys in file {keyfile}.")

    key = algo_parser
    with open(outfile, "w") as c:
        c.write(cipher)

    print("[*] Successfully encripted contents of " + filename + " and saved them under " + outfile)


def decrypt(filename, keyfile, password=None, show_decripted=False, save_decripted=False):

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
    
    plain = hex_nums_to_bytes(plain, n_len)

    print("[*] Successfully decripted contents of " + filename + ".")
    if show_decripted:
        can_be_shown = True
        plain_decoded = ""
        try:
            plain_decoded = plain.decode()
        except:
            can_be_shown = False

        if can_be_shown:     
            print("[*] Result of decription see below.")
            print("*******************************")
            print(plain_decoded)
            print("*******************************")
        else:
            print("[*] Result of decription cannot be shown (is in bytes format).")


    if save_decripted:
        outfile = filename[:-len(ENCRIPTED_EXTENSION)]

        if os.path.isfile(outfile):
            raise FileExistsError("[!] Decripted outfile " + outfile + " already exists.")

        m = open(outfile, "wb")
        m.write(plain)
        m.close()
        print("[*] Contents saved in " + outfile + ".")


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
