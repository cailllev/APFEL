import argparse
import getpass
import os.path
import sys

from getpass import getpass
from utils import *
from key import *

ENCRIPTED_EXTENSION = ".apfel"
KEYFILE_EXTENSION = ".keys"

HEADER_KEYFILE = b"======== PUBLIC KEYFILE - APFEL ========\n"


def init_keyfile(name, password=None):
    if os.path.isfile(name):
        raise FileExistsError("Keyfile " + name + " already exists.")

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

    raw_keys = key_separator.join([init_rsa_key(password).serialize_key(),
                                   init_ecc_key(password).serialize_key(),
                                   init_eg_key(password).serialize_key()])

    with open(name, "wb") as keyfile:
        keyfile.write(HEADER_KEYFILE)
        keyfile.write(raw_keys)


def encrypt(filename: str, keyfile: str, algorithm: str) -> None:
    outfile = filename + ENCRIPTED_EXTENSION

    if not os.path.isfile(filename):
        raise FileNotFoundError(f"[!] File to encrypt {filename} does not exist.")

    if os.path.isfile(outfile):
        raise FileExistsError(f"[!] Encripted outfile {outfile} already exists.")

    with open(filename, "rb") as f:
        plain = f.readlines()

    keys = key_parser(keyfile)
    if algorithm != All:
        keys = filter(lambda k: k.get_name() == algorithm, keys)  # overkill, only finds one anyways

    for key in keys:
        plain = create_encrypted_header(key.get_name()) + key.encrypt(plain)
    cipher = plain

    with open(outfile, "w") as c:
        c.write(cipher)

    print(f"[*] Successfully encripted contents of {filename} and saved them under {outfile}.")


def decrypt(filename: str, keyfile: str, password: str = None,
            show_decripted: bool = False, save_decripted: bool = False):
    if not os.path.isfile(filename):
        raise FileNotFoundError(f"[!] File to decrypt {filename} does not exist.")

    if not password:
        password = getpass("[*] Please enter your password: ")

    with open(filename, "rb") as f:
        cipher = f.readlines()

    keys = key_parser(keyfile)
    while keys:
        algorithm = get_algo_from_cipher(cipher)
        key = get_key_by_name(keys, algorithm)
        keys.remove(key)

        pw_num = get_num_from_password(password, RSA_N_LEN, key.get_salt())
        private = pw_num + key.get_diff()
        cipher = key.decrypt(cipher, private)

    plain = cipher

    print(f"[*] Successfully decripted contents of {filename}.")
    if show_decripted:
        can_be_shown = True
        plain_decoded = ""
        try:
            plain_decoded = plain.decode()
        except UnicodeDecodeError:
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


def print_help():
    s = """
## USAGE ##
init:    python3 apfel.py -i <keyfile>
encrypt: python3 apfel.py -k <keyfile> -e <file to encrypt> [-a RSA | ECC | EG]
decrypt: python3 apfel.py -k <keyfile> -d <file to decrypt> [-v] [-s]
    """
    print(s)
    exit()


def parse_args(argv):
    arg_parser = argparse.ArgumentParser(
        description='Encrypt and Decrypt contents of files via asymmetric algorithm.\n'
                    'The private key is a password of your choosing.')

    arg_parser.add_argument("-i", "--init",
                            help="Init a keyfile, name of keyfile.",
                            type=str)

    arg_parser.add_argument("-k", "--keyfile",
                            help="Encription and Decription mode, name of keyfile",
                            type=str)

    arg_parser.add_argument("-e", "--encrypt",
                            help="Encryption mode, name of file to encrypt.",
                            type=str)

    arg_parser.add_argument("-a", "--algorithm",
                            help="Algorithm name: 'RSA', 'ECC', 'EG' (El-Gamal) or 'All'.",
                            type=str, default=All)

    arg_parser.add_argument("-d", "--decriypt",
                            help="Decryption mode, name of file to decrypt.",
                            type=str)

    arg_parser.add_argument("-v", "--verbose",
                            help="Decription mode, print decripted file.")

    arg_parser.add_argument("-s", "--save",
                            help="Decription mode, save decripted file.")

    return arg_parser.parse_args(argv), arg_parser


if __name__ == "__main__":
    args, _ = parse_args(sys.argv[1:])

    if keyfile_name := args.init:
        print("Init keyfile: " + keyfile_name)
        init_keyfile(keyfile_name)

    elif keyfile_name := args.keyfile:

        if file := args.encrypt:
            if algo := args.algorithm:
                print("[*] Encrypt: " + file)
                encrypt(file, keyfile_name, algo)

        elif file := args.decrypt:
            print("[*] Decrypt: " + file)
            decrypt(file, keyfile_name, None, args.verbose, args.save)

        else:
            print(f"[!] If a keyfile is supplied, the encription or decription flag has to be set!")
            print_help()

    else:
        print(f"[!] Either the init flag or the keyfile flag has to be supplied!")
        print_help()
