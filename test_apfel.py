import unittest
from os import remove, path
from secrets import token_bytes

from apfel import KEYFILE_EXTENSION, ENCRYPTED_EXTENSION, init_keyfile, encrypt, decrypt
from utils import get_algo, check_password_strength
from key import ECCKey, EGKey, RSAKey, KeyHandler, oaep_pad, oaep_unpad, create_salt, get_num_from_password, k0

KEYFILE = "test_keyfile" + KEYFILE_EXTENSION
PASSWORD = "AABBCCdd1!"

TEST_FILE_TO_ENCRYPT = "test.txt"
TEST_FILE_ENCRYPTED = TEST_FILE_TO_ENCRYPT + ENCRYPTED_EXTENSION
DECRYPTED_FILE_NAME = "temp.txt"
FILE_CONTENTS = b"test\ntest\ntest"


class FileEncryptorTest(unittest.TestCase):
    def setUp(self) -> None:
        if not path.exists(KEYFILE):
            init_keyfile(KEYFILE, password=PASSWORD)
        with open(TEST_FILE_TO_ENCRYPT, "wb") as f:
            f.write(FILE_CONTENTS)

    # ***** SERIALIZATION AND STORING ***** #
    def test_serialize_and_deserialize_rsa_key(self):
        rsa_key = RSAKey(PASSWORD)
        s = rsa_key.serialize_key()
        d = RSAKey.deserialize_key(s)
        self.assertEqual(rsa_key, d)

        rsa_key2 = RSAKey(PASSWORD)
        self.assertNotEqual(d, rsa_key2)

    def test_serialize_and_deserialize_ecc_key(self):
        ecc_key = ECCKey(PASSWORD)
        s = ecc_key.serialize_key()
        d = ECCKey.deserialize_key(s)
        self.assertEqual(ecc_key, d)

    def test_serialize_and_deserialize_eg_key(self):
        eg_key = EGKey(PASSWORD)
        s = eg_key.serialize_key()
        d = EGKey.deserialize_key(s)
        self.assertEqual(eg_key, d)

    def test_store_and_deserialize_keys(self):
        ecc_key, eg_key, rsa_key = KeyHandler.parse_keyfile(KEYFILE)

        self.assertIsNotNone(ecc_key)
        self.assertIsNotNone(eg_key)
        self.assertIsNotNone(rsa_key)

        self.assertEqual({"_name", "_n", "_e", "_diff", "_salt"}, rsa_key.__dict__.keys(), )
        self.assertEqual({"_g", "_p", "_diff", "_n", "_salt", "_name"}, ecc_key.__dict__.keys())
        self.assertEqual({"_g", "_p", "_diff", "_n", "_salt", "_name", "_k"}, eg_key.__dict__.keys())

    # ***** OAEP ***** #
    def test_OAEP(self):
        m1 = b"This is a test"
        blocksize = 32
        padded = oaep_pad(m1, blocksize)
        self.assertTrue(len(m1) + k0 <= blocksize)
        self.assertEqual(m1, oaep_unpad(padded, blocksize))

        m2 = b"7his is 4 t3st, bu7_w1th s0me \x8a $peci4l chars and mul71ple b10ck$."
        blocksize = 32
        padded = oaep_pad(m2, blocksize)
        self.assertTrue(len(m2) + k0 > blocksize)
        self.assertEqual(m2, oaep_unpad(padded, blocksize))

    # ***** HASING ***** #
    def test_create_salt(self):
        salt = create_salt()
        self.assertEqual(len(salt), 16)
        self.assertEqual(type(salt), bytes)

    def test_get_num_from_password(self):
        hash_rounds = 1
        salt = create_salt()

        # smaller than 512 bits
        for n_len in range(1, 512):
            d_in = get_num_from_password(PASSWORD, n_len, salt, hash_rounds)
            self.assertTrue(d_in.bit_length() <= n_len - 1)

        # larger than 512 bits
        for n_len in range(512, 4096 + 1, 512):
            d_in = get_num_from_password(PASSWORD, n_len, salt, hash_rounds)
            self.assertTrue(d_in.bit_length() <= n_len - 1)

    # ***** ENCRYPTION ***** #
    def test_rsa_encryption(self):
        rsa_key = RSAKey(PASSWORD)
        c = rsa_key.encrypt(FILE_CONTENTS)
        d = get_num_from_password(PASSWORD, rsa_key._n_len, rsa_key.get_salt()) + rsa_key.get_diff()
        m = rsa_key.decrypt(c, d)
        self.assertEqual(FILE_CONTENTS, m)

    def test_ecc_encryption(self):
        self.assertTrue(False)

    def test_eg_encryption(self):
        self.assertTrue(False)

    def test_encryption_multiple_blocks_multiple_keys(self):
        blocksize = 4096 // 8  # biggest block size of all keys => RSA n bit length

        # TODO: find the bug
        for i in range(10):
            plain = token_bytes(i*blocksize + 1)
            self.test_encryption_multiple_keys(plain)

    def test_encryption_multiple_keys(self, contents=FILE_CONTENTS):
        if contents != FILE_CONTENTS:
            with open(TEST_FILE_TO_ENCRYPT, "wb") as f:
                f.write(contents)

        encrypt(TEST_FILE_TO_ENCRYPT, KEYFILE)

        with open(TEST_FILE_ENCRYPTED, "rb") as f:
            data = f.read()
        self.assertTrue(get_algo(data), "RSA")

        decrypt(TEST_FILE_ENCRYPTED, KEYFILE, password=PASSWORD, save_decripted=DECRYPTED_FILE_NAME)

        with open(DECRYPTED_FILE_NAME, "rb") as f:
            self.assertEqual(contents, f.read())

        remove(DECRYPTED_FILE_NAME)

    # ***** PASSWORD STRENGTH ***** #
    def test_check_password_strength(self):
        self.assertFalse(check_password_strength("012345aA!"))   # fails length
        self.assertTrue(check_password_strength("012345aA!9"))   # okay

        self.assertFalse(check_password_strength("Aaaaaaaaa!"))  # fails at least one number
        self.assertTrue(check_password_strength("Aaaaaaaaa!1"))  # okay

        self.assertFalse(check_password_strength("aaaaaaaa1!"))  # fails uppercase character
        self.assertTrue(check_password_strength("Aaaaaaaa1!"))   # okay

        self.assertFalse(check_password_strength("AAAAAAAA1!"))  # fails lowercase character
        self.assertTrue(check_password_strength("aAAAAAAA1!"))   # okay

        self.assertFalse(check_password_strength("AAAAAAAA1a"))  # fails special character
        self.assertTrue(check_password_strength("aAAAAAAA1!"))   # okay

        self.assertFalse(check_password_strength("Password1!"))  # fails in rockyou
        self.assertTrue(check_password_strength("Password6!"))   # okay

    def tearDown(self):
        files = [KEYFILE, TEST_FILE_TO_ENCRYPT, TEST_FILE_ENCRYPTED, DECRYPTED_FILE_NAME]

        for f in files:
            if path.isfile(f):
                remove(f)
                print("[#] Cleanup, removed " + f)


if __name__ == '__main__':
    unittest.main()
