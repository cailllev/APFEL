from Crypto.Util import number
from hashlib import pbkdf2_hmac
from key import RSAKey
from math import ceil
from os import urandom
from string import punctuation

HASH_ROUNDS = 2**16
RSA_N_LEN = 3072


def get_prime(bit_length):
    print(f"[#] Creating a {bit_length} bit prime...")
    return number.getPrime(bit_length)


def init_rsa_key(password, n_len=RSA_N_LEN, hash_rounds=HASH_ROUNDS):
    diff = ceil(pow(2, n_len / 2 - 100) / 2)  # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#page=62
    p_len = n_len // 2 + diff
    q_len = n_len - p_len

    p = get_prime(p_len)
    q = get_prime(q_len)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 0x10001

    salt = create_salt()
    d_in, bit_diff = get_num_from_password(password, n_len, salt, hash_rounds)

    while True:
        try:
            d = pow(e, -1, phi)
            diff = d - d_in
            break

        except ValueError:
            pass

    del p
    del q
    del phi

    return RSAKey(n, e, diff)


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


def create_salt():
    return urandom(16)


def get_num_from_password(password, n_len, salt, rounds):
    hashed = pbkdf2_hmac("sha512", password.encode(), salt.encode(), rounds)
    d_in = int.from_bytes(hashed, "big")
    bit_diff = n_len - d_in.bit_length()

    # if d_in is bigger than n -> mod n so it fits
    # only happens in testing, when n < 512 is allowed
    d_in = d_in % n_len

    return d_in, bit_diff
