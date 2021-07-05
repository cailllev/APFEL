import os
import secrets
import string
import unittest

from random import choice

from file_encriptor import *
from utils import *

RSA_KEYFILE = "test_rsa_keyfile" + KEYFILE_EXTENSION
PASSWORD = "AABBCCdd1!"

TEST_FILE_TO_ENCRYPT = "test.txt"
TEST_FILE_ENCRYPTED = TEST_FILE_TO_ENCRYPT + ENCRIPTED_EXTENSION
FILE_CONTENTS = 'test\ntest\ntest'


class FileEncriptorTest(unittest.TestCase):
    def test_init_rsa_key(self):
        rsa_key = init_rsa_key(PASSWORD)

        s = rsa_key.serialize_key()
        name = s["_name"]
        n = s["_n"]
        e = s["_e"]
        diff = s["_diff"]

        self.assertEqual(name, RSA)
        self.assertTrue(int(n).bit_length() >= RSA_N_LEN - 1)
        self.assertEqual(e, RSA_E)
        self.assertTrue(diff >= 0 and diff.bit_length() <= RSA_N_LEN)

    def test_serialize_and_deserialize_rsa_key(self):
        rsa_key = init_rsa_key(PASSWORD)
        s = rsa_key.serialize_key()
        d = RSAKey.deserialize_key(s)
        self.assertEqual(rsa_key, d)

        rsa_key2 = init_rsa_key(PASSWORD)
        self.assertNotEqual(d, rsa_key2)

    def test_pad(self):
        self.assertTrue(False)

    def test_create_salt(self):
        salt = create_salt()
        self.assertEqual(len(salt), 16)

    def test_get_num_from_password_standard(self):
        d_in = get_num_from_password(PASSWORD, RSA_N_LEN, create_salt(), HASH_ROUNDS)
        self.assertTrue(d_in.bit_length() < RSA_N_LEN)
        self.assertTrue(d_in.bit_length() >= RSA_N_LEN - 512)

    def test_get_num_from_password_exhaustive(self):
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
        m = rsa_key.decrypt(c)
        self.assertEqual(FILE_CONTENTS, m)

    def test_rsa_encryption_non_ascii(self):
        rsa_key = init_rsa_key(PASSWORD)

        plain = []
        for i in range(1, 256):
            plain.append(i)
        plain = bytearray(plain)

        c = rsa_key.encrypt(plain)
        m = rsa_key.decrypt(c)

        self.assertEqual(plain, m)

    def test_rsa_encryption_multiple_blocks(self):
        rsa_key = init_rsa_key(PASSWORD)

        random_file_contents = ""

        for j in range(n_len):  # test every length of last block
            if j % 16 == 0:
                print("*********************************")
                print(str(j) + " / 128 done ...")
                print("*********************************")

            for i in range(n_len * 15 + j):  # 15 full blocks + 1 varing block 
                random_file_contents += choice(string.ascii_letters)

            f = open(TEST_FILE_TO_ENCRYPT, "w")
            f.write(random_file_contents)
            f.close()

            try:
                os.remove(TEST_FILE_TO_ENCRYPT + ENCRIPTED_EXTENSION)
            except:
                pass

            encript(TEST_FILE_TO_ENCRYPT, keyfile_out)

            try:
                os.remove(TEST_FILE_TO_ENCRYPT)
            except:
                pass

            decript(TEST_FILE_TO_ENCRYPT + ENCRIPTED_EXTENSION, keyfile_out, PASSWORD, False, True)

            f = open(TEST_FILE_TO_ENCRYPT, "r")
            plain = "".join(f.readlines())
            f.close()

            self.assertEqual(random_file_contents, plain)

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
        files = [RSA_KEYFILE, TEST_FILE_TO_ENCRYPT, TEST_FILE_ENCRYPTED]

        for f in files:
            if os.path.isfile(f):
                os.remove(f)
                print("[#] Cleanup, removed " + f)


if __name__ == '__main__':
    unittest.main()
