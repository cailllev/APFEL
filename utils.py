from hashlib import pbkdf2_hmac
from string import punctuation
from secrets import token_bytes

HASH_ROUNDS = 2**16
HEADER_TEXT = b"APFEL ENCRYPTED FILE: "
HEADER_SEPARATOR = b"\n"

assert HEADER_SEPARATOR not in HEADER_TEXT, "HEADER_TEXT cannot contain HEADER_SEPARATOR"


def create_header(algo: str) -> bytes:
    return HEADER_TEXT + algo.encode() + HEADER_SEPARATOR


def get_algo(cipher: bytes) -> str:
    header = cipher.split(HEADER_SEPARATOR)[0]
    return header.replace(HEADER_TEXT, b"").decode()


def remove_header(cipher: bytes) -> bytes:
    header_end = cipher.index(HEADER_SEPARATOR) + 1
    return cipher[header_end:]


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

    with open("helpers/rockyou_shortened.txt", "rb") as f:
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

    # append hashes until hash is >= n_len -> password123 -> d4fe -> d4fe36ad -> d4fe36ad04ef -> ...
    while d_in_next.bit_length() <= n_len:
        hashed += pbkdf2_hmac("sha512", hashed, salt, rounds)
        d_in_next = int.from_bytes(hashed, "big")

    # now if d_in_next is bigger than n -> rightshift so it fits
    if d_in_next.bit_length() >= n_len - 1:
        return d_in_next >> (d_in_next.bit_length() - n_len + 1)

    return d_in
