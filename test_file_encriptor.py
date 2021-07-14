import os
import unittest

from file_encriptor import *
from utils import *
from key import *

KEYFILE = "test_keyfile" + KEYFILE_EXTENSION
PASSWORD = "AABBCCdd1!"

TEST_FILE_TO_ENCRYPT = "test.txt"
TEST_FILE_ENCRYPTED = TEST_FILE_TO_ENCRYPT + ENCRIPTED_EXTENSION
FILE_CONTENTS = b"test\ntest\ntest"


class FileEncriptorTest(unittest.TestCase):
    def test_serialize_and_deserialize_rsa_key(self):
        rsa_key = init_rsa_key(PASSWORD)
        s = rsa_key.serialize_key()
        d = RSAKey.deserialize_key(s)
        self.assertEqual(rsa_key, d)

        rsa_key2 = init_rsa_key(PASSWORD)
        self.assertNotEqual(d, rsa_key2)

    def test_serialize_and_deserialize_ecc_key(self):
        ecc_key = init_ecc_key(PASSWORD)
        s = ecc_key.serialize_key()
        d = ECCKey.deserialize_key(s)
        self.assertEqual(ecc_key, d)

    def test_serialize_and_deserialize_eg_key(self):
        eg_key = init_eg_key(PASSWORD)
        s = eg_key.serialize_key()
        d = EGKey.deserialize_key(s)
        self.assertEqual(eg_key, d)

    def test_store_and_deserialize_keys(self):
        init_keyfile(KEYFILE, PASSWORD)
        rsa_key, ecc_key, eg_key = key_parser(KEYFILE)

        self.assertIsNotNone(rsa_key)
        self.assertIsNotNone(ecc_key)
        self.assertIsNotNone(eg_key)

        self.assertEqual(set(rsa_key.__dict__), {"_name", "_n", "_e", "_diff", "_salt"})
        self.assertEqual(set(ecc_key.__dict__), {"_g", "_p", "_diff", "_n", "_salt", "_name"})
        self.assertEqual(set(eg_key.__dict__), {"_g", "_p", "_diff", "_n", "_salt", "_name"})

    def test_OEAP(self):
        m1 = b"This is a test"
        blocksize = 32
        padded = OAEP_pad(m1, blocksize)
        self.assertTrue(len(m1) + k0 <= blocksize)
        self.assertEqual(m1, OAEP_unpad(padded, blocksize))

        m2 = b"7his is 4 t3st, bu7_w1th s0me \x8a $peci4l chars and mul71ple b10ck$."
        blocksize = 32
        padded = OAEP_pad(m2, blocksize)
        self.assertTrue(len(m2) + k0 > blocksize)
        self.assertEqual(m2, OAEP_unpad(padded, blocksize))

    """
    def test_d_from_password(self):
        rsa_key, d1 = init_rsa_key(PASSWORD)
        d2 = get_num_from_password(PASSWORD, RSA_N_LEN, rsa_key.get_salt()) + rsa_key.get_diff()
        self.assertEqual(d1, d2)
    """

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
        for n_len in range(512, 4096+1, 512):
            d_in = get_num_from_password(PASSWORD, n_len, salt, hash_rounds)
            self.assertTrue(d_in.bit_length() <= n_len - 1)

    def test_rsa_encryption(self):
        rsa_key = init_rsa_key(PASSWORD)
        c = rsa_key.encrypt(FILE_CONTENTS)
        d = get_num_from_password(PASSWORD, RSA_N_LEN, rsa_key.get_salt()) + rsa_key.get_diff()
        m = rsa_key.decrypt(c, d)
        self.assertEqual(FILE_CONTENTS, m)

    def test_ecc_encryption(self):
        self.assertTrue(False)

    def test_eg_encryption(self):
        self.assertTrue(False)

    def test_multiple_key_encryption(self):
        with open(TEST_FILE_TO_ENCRYPT, "wb") as f:
            f.write(FILE_CONTENTS)

        init_keyfile(KEYFILE, PASSWORD)
        _, _, eg_key = key_parser(KEYFILE)

        encrypt(TEST_FILE_TO_ENCRYPT, KEYFILE, All, True)
        algorithm = get_algo_from_cipher(open(TEST_FILE_ENCRYPTED).readlines())
        self.assertEqual(algorithm, EG)

        decrypt(TEST_FILE_ENCRYPTED, KEYFILE, PASSWORD, save_decripted=TEST_FILE_TO_ENCRYPT)
        decrypted = open(TEST_FILE_TO_ENCRYPT).readlines()
        self.assertEqual(FILE_CONTENTS, decrypted)

    def test_encryption_multiple_blocks(self):
        rsa_key = init_rsa_key(PASSWORD)
        random_file_contents = ""

        for j in range(RSA_N_LEN):  # test every length of last block
            if j % 16 == 0:
                print("*********************************")
                print(str(j) + " / 128 done ...")
                print("*********************************")

                self.assertTrue(False)

    def test_check_password_strength(self):
        self.assertFalse(check_password_strength("012345aA!"))  # fails length
        self.assertTrue(check_password_strength("012345aA!9"))  # okay

        self.assertFalse(check_password_strength("Aaaaaaaaa!"))  # fails at least one number
        self.assertTrue(check_password_strength("Aaaaaaaaa!1"))  # okay

        self.assertFalse(check_password_strength("aaaaaaaa1!"))  # fails uppercase character
        self.assertTrue(check_password_strength("Aaaaaaaa1!"))  # okay

        self.assertFalse(check_password_strength("AAAAAAAA1!"))  # fails lowercase character
        self.assertTrue(check_password_strength("aAAAAAAA1!"))  # okay

        self.assertFalse(check_password_strength("AAAAAAAA1a"))  # fails special character
        self.assertTrue(check_password_strength("aAAAAAAA1!"))  # okay

        self.assertFalse(check_password_strength("Password1!"))  # fails in rockyou
        self.assertTrue(check_password_strength("Password6!"))  # okay

    def tearDown(self):
        files = [KEYFILE, TEST_FILE_TO_ENCRYPT, TEST_FILE_ENCRYPTED]

        for f in files:
            if os.path.isfile(f):
                os.remove(f)
                print("[#] Cleanup, removed " + f)


if __name__ == '__main__':
    unittest.main()
