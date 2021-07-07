import pickle

from abc import ABC, abstractmethod
from Crypto.Util.number import long_to_bytes, bytes_to_long
from typing import List

# OEAS padding
k0 = 1
k1 = 2

# cipher spec
RSA_N_LEN = 3072
RSA_E = 0x10001

# names
RSA = "RSA"
ECC = "ECC"
EG = "EG"
All = "All"

# TODO find better method to separate serialized objects and encrypted stuff
SEPARATOR = b"A" * (RSA_N_LEN // 8)


# https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
# TODO implement this correctly
def pad(m: bytes, blocksize: int) -> bytes:
    ms = []
    for i in range(0, len(m), blocksize):
        block = m[i*blocksize:(i+1)*blocksize]
        ms.append(block)
    return ms


# TODO implement this correctly
def unpad(m: bytes) -> bytes:
    print(m)
    pass


class Key(ABC):
    def __init__(self):
        self._name = None
        self._diff = None
        self._salt = None

    def serialize_key(self) -> bytes:
        return pickle.dumps(self)

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
    def deserialize_key(raw_key: bytes) -> object:
        return pickle.loads(raw_key)

    @abstractmethod
    def encrypt(self, m: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, c: bytes, private: int) -> bytes:
        ...


# TODO encryption & decryption for algos
class RSAKey(Key):
    def __init__(self, n: int, e: int, diff: int, salt: bytes):
        super().__init__()

        self._name = RSA
        self._n = n
        self._e = e
        self._diff = diff
        self._salt = salt

    def encrypt(self, m: bytes) -> bytes:
        cipher = b""
        ms = pad(m, RSA_N_LEN // 8)  # blocksize in bytes

        for m in ms:  # TODO add anti timing attack measures, add padding
            m = bytes_to_long(m)
            c = pow(m, self._e, self._n)
            cipher += long_to_bytes(c) + SEPARATOR

        return cipher

    def decrypt(self, c: bytes, d: int) -> bytes:
        plain = b""
        cs = c.split(SEPARATOR)

        for c in cs:  # TODO add anti timing attack measures, add padding
            if len(c) == 0:  # TODO maybe redundant with correct padding
                continue
            c = bytes_to_long(c)
            m = pow(c, d, self._n)
            plain += long_to_bytes(m)

        del d
        return plain


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


def key_parser(keyfile: str) -> List[Key]:
    with open(keyfile, "rb") as k:
        raw_keys = k.readlines()[1:]  # remove header

    # eliminate randomly created newlines and then split with unique separator
    raw_keys = b"".join(raw_keys)
    raw_keys = raw_keys.split(SEPARATOR)

    algos = [RSAKey, ECCKey, EGKey]
    parsed_keys = []

    for raw_key in raw_keys:
        for algo in algos:
            try:
                key = algo.deserialize_key(raw_key)
                parsed_keys.append(key)
                break
            except pickle.UnpicklingError:
                pass
    return parsed_keys


def get_key_by_name(keys: Key, name: str) -> Key:
    for key in keys:
        if key.get_name() == name:
            return key
    return None
