import unittest
import os

from file_encriptor import *
from sage.all import is_prime


class MyTestCase(unittest.TestCase):
    def test_new_d(self):
        name = "test_keyfile" + KEYFILE_EXTENSION
        password = "AABBCC"
        try:
            os.remove(name)
        except:
            pass

        init_keyfile(name, password)
        password_as_int = string_to_number(password)

        k = open(name, "r")
        _, _, diff = k.readlines()[1:-1]
        k.close()

        d = int(diff) + password_as_int
        print("d calc: " + d)

        self.assertTrue(is_prime(d))

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



if __name__ == '__main__':
    unittest.main()
