import pickle

from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import pbkdf2_hmac
from secrets import token_bytes
from typing import List

# keys spec
RSA_N_LEN = 3072
RSA_E = 0x10001

# OAEP
k0 = 16  # byte length for OEAP
padding = b"\x00"
padding_int = int.from_bytes(padding, "big")

# names
RSA = "RSA"
ECC = "ECC"
EG = "EG"
All = "All"


def xor(a: bytes, b: bytes) -> bytes:
    return long_to_bytes(bytes_to_long(a) ^ bytes_to_long(b))


def OAEP_hash(b: bytes, length: int) -> bytes:
    hashed = pbkdf2_hmac("sha512", b, b"$al7y_s4lt", 1)
    return hashed[:length]


def OAEP_pad(m: bytes, n: int) -> bytes:
    if n <= k0:
        raise Exception(f"[!] Blocksize ({n} bytes) must be bigger than k0 ({k0} bytes).")

    # split messages so that len(m) <= blocksize - k0
    ms = [m[i:i + n - k0] for i in range(0, len(m), n - k0)]
    padded = []

    for m in ms:
        # messages are padded with k1 zeros to be n − k0 bits in length
        # -> len(m) + k1 = n - k0
        k1 = n - k0 - len(m)
        m += k1 * padding

        # r is a randomly generated k0-bit string
        r = token_bytes(k0)

        # G expands the k0 bits of r to n − k0 bits
        g = OAEP_hash(r, n - k0)

        # X = m00...0 ⊕ G(r)
        x = xor(m, g)

        # H reduces the n − k0 bits of X to k0 bits
        h = OAEP_hash(x, k0)

        # Y = r ⊕ H(X)
        y = xor(r, h)

        # The output is X || Y where X is shown in the diagram as the leftmost block and Y as the rightmost block
        padded.append(x + y)

    return padded


def OAEP_unpad(ms: bytes, n: int) -> bytes:
    unpadded = []

    for m in ms:
        x = m[:-k0]
        y = m[-k0:]

        # recover the random string as r = Y ⊕ H(X)
        h = OAEP_hash(x, k0)
        r = xor(y, h)

        # recover the message as m00...0 = X ⊕ G(r)
        g = OAEP_hash(r, n - k0)
        m = xor(x, g)

        while m[-1] == padding_int:
            m = m[:-1]

        unpadded.append(m)

    return b"".join(unpadded)


class Key(ABC):
    def __init__(self):
        self._name = None
        self._diff = None
        self._salt = None

    def serialize_key(self) -> str:
        return b64encode(pickle.dumps(self)).decode()

    def __str__(self) -> str:
        return str(self.__dict__.keys())

    def __eq__(self, other) -> bool:
        if type(other) is not type(self):
            return False

        for k, v in self.__dict__.items():
            if k not in other.__dict__:
                return False
            if v != other.__dict__[k]:
                return False

        return True

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def get_name(self) -> str:
        return self._name

    def get_diff(self) -> int:
        return self._diff

    def get_salt(self) -> bytes:
        return self._salt

    @staticmethod
    def deserialize_key(raw_key: str) -> object:
        return pickle.loads(b64decode(raw_key))

    @abstractmethod
    def encrypt(self, m: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, c: bytes, private: int) -> bytes:
        ...


# TODO encryption & decryption for algos
# TODO correct params
class ECCKey(Key):
    def __init__(self, n: int, p: int, g: int, diff: int, salt: bytes):
        super().__init__()

        self._name = ECC
        self._n = n
        self._p = p
        self._g = g
        self._diff = diff
        self._salt = salt

    def encrypt(self, m: bytes) -> bytes:
        pass

    def decrypt(self, c: bytes, private: int) -> bytes:
        pass


class EGKey(Key):
    def __init__(self, n: int, p: int, g: int, diff: int, salt: bytes):
        super().__init__()

        self._name = EG
        self._n = n
        self._p = p
        self._g = g
        self._diff = diff
        self._salt = salt

        # private
        self._k = None

    def encrypt(self, m: bytes) -> bytes:
        pass

    def decrypt(self, c: bytes, private: int) -> bytes:
        pass


class RSAKey(Key):
    def __init__(self, n: int, e: int, diff: int, salt: bytes):
        super().__init__()

        self._name = RSA
        self._n = n
        self._e = e
        self._diff = diff
        self._salt = salt

    def encrypt(self, plain: bytes) -> str:
        cipher = []
        ms = OAEP_pad(plain, RSA_N_LEN // 8)  # blocksize in bytes

        for m in ms:  # TODO add anti timing attack measures
            c = pow(bytes_to_long(m), self._e, self._n)
            c = b64encode(c).decode()
            cipher.append(c)

        return "\n".join(cipher)

    def decrypt(self, cipher: List[str], d: int) -> bytes:
        plain = []

        for c in cipher:  # TODO add anti timing attack measures
            c = b64decode(c)
            m = pow(c, d, self._n)
            plain.append(m)
        del d

        plain = OAEP_unpad(plain, RSA_N_LEN)
        return plain


def key_parser(keyfile: str) -> List[Key]:
    with open(keyfile, "r") as k:
        raw_keys = k.readlines()[1:]  # remove header

    algos = [RSAKey, ECCKey, EGKey]
    parsed_keys = []

    for raw_key in raw_keys:
        for algo in algos:
            try:
                key = algo.deserialize_key(raw_key)
                parsed_keys.append(key)
                algos.remove(algo)
            except pickle.UnpicklingError:
                continue

    return parsed_keys


def get_key_by_name(keys: Key, name: str) -> Key:
    for key in keys:
        if key.get_name() == name:
            return key
    return None
