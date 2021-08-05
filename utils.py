from hashlib import pbkdf2_hmac
from string import punctuation
from secrets import token_bytes

HASH_ROUNDS = 2**16


def create_encrypted_header(algo: str) -> str:
    return "======== " + algo + " ========\n"


def get_algo_from_cipher(cipher: str) -> str:
    header = cipher.split("\n")[0]
    return header.replace("=", "").replace(" ", "").replace("\n", "")


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


def create_salt() -> bytes:
    return token_bytes(16)


def get_num_from_password(password: str, n_len: int, salt: bytes, rounds: int = HASH_ROUNDS) -> int:

    hashed = pbkdf2_hmac("sha512", password.encode(), salt, rounds)
    d_in_next = int.from_bytes(hashed, "big")
    d_in = 0

    # if d_in is bigger than n -> rightshift so it fits
    # only happens in testing, when n < 512 bit is allowed
    if d_in_next.bit_length() >= n_len:
        return d_in_next >> d_in_next.bit_length() - n_len + 1

    # else append hashes until big enough -> password123 -> d4fe -> d4fe36ad -> ...
    while d_in_next.bit_length() <= n_len:
        hashed += pbkdf2_hmac("sha512", hashed, salt, rounds)
        d_in_next = int.from_bytes(hashed, "big")
        d_in = d_in_next >> 1  # shift so it's always smaller than n

    return d_in
