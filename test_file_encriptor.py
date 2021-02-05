import unittest
import os

from file_encriptor import *
from sage.all import is_prime


class MyTestCase(unittest.TestCase):
    def test_init_keyfile(self):
        short_name = "test_keyfile"
        name = "test_keyfile" + KEYFILE_EXTENSION
        password = "AABBCC"
        try:
            os.remove(name)
        except:
            pass

        n_out, e_out, d_out = init_keyfile(short_name, password)
        password_as_int = string_to_number(password)

        k = open(name, "r")
        n, e, diff = k.readlines()[1:-1]
        k.close()

        d = int(diff) + password_as_int
        self.assertTrue(is_prime(d))

        self.assertEqual(n, str(n_out).strip())
        self.assertEqual(e, str(e_out).strip())
        self.assertEqual(d, str(d_out).strip())


    def test_convert(self):
        s = "A"
        i = 65
        self.assertEqual(string_to_number(s), i)
        self.assertEqual(number_to_string(i), s)

        s = "AA"
        i = 16705  # 256*65 + 1*65
        self.assertEqual(string_to_number(s), i)
        self.assertEqual(number_to_string(i), s)

        s = "AABBCC"
        i = 0

        for m in range(len(s)):
            c = ord(s[-(m+1)])  # from last to first
            mul = 256**m
            i += c * mul

        self.assertEqual(string_to_number(s), i)
        self.assertEqual(number_to_string(i), s)

    def test_encript_and_decript(self):
        short_name = "test_keyfile"
        keyfile = "test_keyfile" + KEYFILE_EXTENSION
        password = "AABBCC"
        try:
            os.remove(keyfile)
        except:
            pass

        test_file_to_encript = "test_file.txt"
        os.system(f"echo 'test\ntest\ntest' > {test_file_to_encript}")

        init_keyfile(short_name, password)
        encript(test_file_to_encript, keyfile)
        decript()



if __name__ == '__main__':
    unittest.main()
