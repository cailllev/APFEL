import unittest
import os
import string

from file_encriptor import *
from sage.all import is_prime
from random import choice


keyfile = "test_keyfile"
keyfile_out = keyfile + KEYFILE_EXTENSION
password = "AABBCC"


def create_keyfile(n_len):
    try:
        os.remove(keyfile_out)
    except:
        pass

    return init_keyfile(keyfile, password, n_len)


class FileEncriptorTest(unittest.TestCase):
    def test_init_keyfile(self):
        n_bit_len = 256
        n_out, e_out, d_out = create_keyfile(n_bit_len)
        password_as_int = int(string_to_hex_nums(password, n_bit_len)[0], 16)

        k = open(keyfile_out, "r")
        n, e, diff = k.readlines()[1:-1]
        k.close()
    
        quotient, remainder = diff.split(":")
        d = password_as_int + int(quotient) * password_as_int + int(remainder)
        self.assertEqual(d, d_out)

        self.assertEqual(n.strip(), str(n_out).strip())
        self.assertEqual(e.strip(), str(e_out).strip())
        self.assertEqual(d, d_out)

    def test_len_n(self):
        n_bit_len = 128

        for _ in range(100):
            n_out, e_out, d_out = create_keyfile(n_bit_len)

            k = open(keyfile_out, "r")
            n, _, _ = k.readlines()[1:-1]
            k.close()

            self.assertTrue(int(n).bit_length() >= n_bit_len)

    def test_init_keyfile_big_password(self):
        n_bit_len = 128
        password = "AA" * (n_bit_len//8)

        create_keyfile(n_bit_len)  # must pass

        password += "B"

        try:
            os.remove(keyfile_out)
        except:
            pass

        self.assertRaises(AssertionError, init_keyfile, keyfile, password, n_bit_len)

    def test_convert(self):
        n_bit_len = 8

        s = "A"
        i = ["41"]
        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i), s)

        s = "AA"
        i = ["41", "41"]
        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i), s)

        s = "AABBCC"
        i = ["41", "41", "42", "42", "43", "43"]

        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i), s)

        n_bit_len = 16
        s = "AABBCCDD"
        i = ["4141", "4242", "4343", "4444"]

        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i), s)

    def test_encript_and_decript_single_block(self):
        create_keyfile(2048)

        test_file_to_encript = "test.txt"
        file_contents = 'test\ntest\ntest'

        f = open(test_file_to_encript, "w")
        f.write(file_contents)
        f.close()
        
        try:
            os.remove(test_file_to_encript + ENCRIPTED_EXTENSION)
        except:
            pass

        encript(test_file_to_encript, keyfile_out)

        try:
            os.remove(test_file_to_encript)
        except:
            pass

        decript(test_file_to_encript + ENCRIPTED_EXTENSION, keyfile_out, password, True, True)

        f = open(test_file_to_encript, "r")
        plain = "".join(f.readlines())
        f.close()

        self.assertEqual(file_contents, plain)

    def test_encript_and_decript_multiple_blocks(self):
        n_len = 128
        create_keyfile(n_len)

        test_file_to_encript = "test_file.txt"
        file_contents = ""

        for j in range(n_len):  # test every length of last block
            if j % 16 == 0:
                print("*********************************")
                print(str(j) + " / 128 done ...")
                print("*********************************")

            for i in range(n_len * 15 + j):  # 15 full blocks + 1 varing block 
                file_contents += choice(string.ascii_letters)

            f = open(test_file_to_encript, "w")
            f.write(file_contents)
            f.close()

            try:
                os.remove(test_file_to_encript + ENCRIPTED_EXTENSION)
            except:
                pass

            encript(test_file_to_encript, keyfile_out)

            try:
                os.remove(test_file_to_encript)
            except:
                pass

            decript(test_file_to_encript + ENCRIPTED_EXTENSION, keyfile_out, password, False, True)

            f = open(test_file_to_encript, "r")
            plain = "".join(f.readlines())
            f.close()

            self.assertEqual(file_contents, plain)


if __name__ == '__main__':
    unittest.main()
