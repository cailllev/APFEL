from Crypto.Util import number
from hashlib import pbkdf2_hmac
from os import urandom
from string import punctuation

from key import RSAKey, ECCKey, RSA, ECC

HASH_ROUNDS = 2**16
RSA_N_LEN = 3072
RSA_E = 0x10001


def get_encrypted_header(algo: str) -> str:
    return f"======== {algo} ========"


def get_algo_from_encrypted_file(encrypted_file: str) -> str:
    with open(encrypted_file, "r") as f:
        header = f.readline()
    return header.replace("=", "").replace(" ", "")


def init_rsa_key(password):
    print(f"[#] Init RSA keys.")

    q_len = RSA_N_LEN // 2
    p_len = RSA_N_LEN - q_len + 1
    p = q = 0

    # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#page=62
    while p - q <= pow(2, int(RSA_N_LEN / 2 - 100)) and (p*q).bit_length() < RSA_N_LEN:
        p = number.getPrime(p_len)
        q = number.getPrime(q_len)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = RSA_E

    salt = create_salt()
    d_in = get_num_from_password(password, RSA_N_LEN, salt, HASH_ROUNDS)

    while True:
        try:
            d = pow(e, -1, phi)
            diff = d - d_in
            break

        except ValueError:  # i.e. no inverse found
            pass

    del p, q, phi, d, d_in
    return RSAKey(n, e, diff, salt)


def init_ecc_key(password):
    return ECCKey(0, 0, 0, 0, b"")


def init_eg_key(password):
    return ECCKey(0, 0, 0, 0, b"")


def check_password_strength(password, shorten_rockyou=False):
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

    # only skip this if in "shorten rockyou" mode
    if not shorten_rockyou:
        with open("rockyou_shortened.txt", "rb") as f:
            for pw in f:
                if password.encode() == pw[:-1]:
                    print("[!] Password must not be in 'rockyou.txt'.")
                    return False

    return True


def shorten_rockyou_txt():
    valid_passwords = []
    with open("rockyou.txt", "rb") as f:
        for password in f:
            try:
                if check_password_strength(password[:-1].decode(), True):
                    valid_passwords.append(password[:-1])
            except UnicodeDecodeError:
                pass

    with open("rockyou_shortened.txt", "wb") as f:
        f.write(b"\n".join(valid_passwords))


def create_salt() -> bytes:
    return urandom(16)


def get_num_from_password(password: str, n_len: int, salt: bytes, rounds: int = HASH_ROUNDS) -> int:

    hashed = pbkdf2_hmac("sha512", password.encode(), salt, rounds)
    d_in_next = int.from_bytes(hashed, "big")
    d_in = 0

    # if d_in is bigger than n -> rightshift so it fits
    # only happens in testing, when n < 512 bit is allowed
    if d_in_next.bit_length() >= n_len:
        return d_in_next >> d_in_next.bit_length() - n_len + 1

    # else append hashes until big enough -> password123 -> d4fe -> d4fe36ad
    while d_in_next.bit_length() <= n_len:
        hashed += pbkdf2_hmac("sha512", hashed, salt, rounds)
        d_in = d_in_next >> 1
        d_in_next = int.from_bytes(hashed, "big")

    return d_in


if __name__ == "__main__":
    input("[*] Proceed to shorten 'rockyou.txt'?")
    shorten_rockyou_txt()
