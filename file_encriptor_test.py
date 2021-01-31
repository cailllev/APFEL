import unittest

from file_encriptor import *
from sage.all import is_prime


class MyTestCase(unittest.TestCase):
    def test_new_d(self):
        name = "keyfile"
        password = "ABC"
        init_keyfile(name, password)  # b"ABC" -> # 4276803
        password_as_int = 4276803

        k = open(name, "r")
        _, _, diff = k.readlines()[1:-1]
        k.close()

        self.assertTrue(is_prime(diff + password_as_int))


if __name__ == '__main__':
    unittest.main()
