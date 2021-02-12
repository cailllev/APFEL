import unittest
import os
import string

from file_encriptor import *
from sage.all import is_prime
from random import choice


keyfile = "test_keyfile"
keyfile_out = keyfile + KEYFILE_EXTENSION
password = "AABBCC"

test_file_to_encript = "test.txt"
file_contents = 'test\ntest\ntest'


def create_keyfile(n_len, hash_rounds=12):
    try:
        os.remove(keyfile_out)
    except:
        pass

    return init_keyfile(keyfile, password, n_len, hash_rounds)


class FileEncriptorTest(unittest.TestCase):
    def test_init_keyfile(self):
        n_bit_len = 256
        n_out, e_out, _, _ = create_keyfile(n_bit_len)

        k = open(keyfile_out, "r")
        n, e, _ = k.readlines()[1:-1]
        k.close()

        self.assertEqual(n.strip(), str(n_out).strip() + ":" + str(n_bit_len))
        self.assertEqual(e.strip(), str(e_out).strip())

    def test_len_n(self):
        n_bit_len = 128

        for _ in range(100):
            create_keyfile(n_bit_len)

            k = open(keyfile_out, "r")
            n, _, _ = k.readlines()[1:-1]
            k.close()

            n = int(n.split(":")[0])

            self.assertTrue(int(n).bit_length() >= n_bit_len)

    def test_convert(self):
        n_bit_len = 8

        s = "A"
        i = ["41"]
        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i, n_bit_len), s)

        s = "AA"
        i = ["41", "41"]
        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i, n_bit_len), s)

        s = "AABBCC"
        i = ["41", "41", "42", "42", "43", "43"]

        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i, n_bit_len), s)

        n_bit_len = 16
        s = "AABBCCDD"
        i = ["4141", "4242", "4343", "4444"]

        self.assertEqual(string_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_string(i, n_bit_len), s)
 
    def test_create_salt(self):    
    	rounds = 16
    	salt = create_salt(rounds)
    	salt_rounds = salt.split("$")[2]

    	self.assertEqual(salt_rounds, str(rounds))

    def test_get_num_from_password(self):
        n_len = 256
        _, _, d, d_in = create_keyfile(n_len)

        f = open(keyfile_out, "r")
        _, _, diff = f.readlines()[1:-1]
        f.close()

        salt, quotient, remainder = diff.split(":")
        d_in_calc, _ = get_num_from_password(password, n_len, salt)
        d_calc = d_in_calc + int(quotient) * d_in_calc + int(remainder)

        self.assertEqual(d, d_calc)
        self.assertEqual(d_in, d_in_calc)
        

    def test_get_num_from_password_exhaustive(self):
        n_len = 8
        salt = create_salt(4)

        for _ in range(1000):
            d_in, bit_diff = get_num_from_password("AAAA", n_len, salt)

            self.assertEqual(bit_diff, 0)
            self.assertTrue(2**7 <= d_in)
            self.assertTrue(d_in < 2**8)

    def test_get_num_from_long_password(self):
        n_len = 8
        salt = create_salt(12)
        password = "A"*1000

        d_in, bit_diff = get_num_from_password(password, n_len, salt)

        self.assertEqual(bit_diff, 0)
        self.assertTrue(2**7 <= d_in)
        self.assertTrue(d_in < 2**8)

    def test_padding(self):
    	n_len = 128
    	block_size = 2*n_len//8
    	chars_in_block = block_size//2

    	for j in range(8):
    		chars = chars_in_block * j

	    	for i in range(chars, chars + chars_in_block):
	    		string = "P"*(i+1)  # P = 0x50
	    		as_hex_nums = string_to_hex_nums(string, n_len)
	    		
	    		self.assertEqual(len(as_hex_nums), j+1)

	    		self.assertEqual(len(as_hex_nums[-1]), block_size)
	    		self.assertEqual(as_hex_nums[-1].count("50"), 1 + i % chars_in_block)
	    		self.assertEqual(as_hex_nums[-1].count("0"), block_size - 1 - (i % chars_in_block))

	    		as_string = hex_nums_to_string(as_hex_nums, n_len)
	    		self.assertEqual(string, as_string)

    def test_encript_and_decript_small_single_block(self):
        create_keyfile(n_len=256, hash_rounds=12)

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

        try:
            os.remove(test_file_to_encript)
        except:
            pass

    def test_encript_and_decript_single_block(self):
        create_keyfile(n_len=2048, hash_rounds=12)


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

        try:
            os.remove(test_file_to_encript)
        except:
            pass

    def test_encript_and_decript_multiple_blocks(self):
        n_len = 128
        create_keyfile(n_len)

        random_file_contents = ""

        for j in range(n_len):  # test every length of last block
            if j % 16 == 0:
                print("*********************************")
                print(str(j) + " / 128 done ...")
                print("*********************************")

            for i in range(n_len * 15 + j):  # 15 full blocks + 1 varing block 
                random_file_contents += choice(string.ascii_letters)

            f = open(test_file_to_encript, "w")
            f.write(random_file_contents)
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

            self.assertEqual(random_file_contents, plain)

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

    def tearDown(self):
    	files = [keyfile, keyfile_out, test_file_to_encript, test_file_to_encript + ENCRIPTED_EXTENSION]

    	for f in files:
    		if os.path.isfile(f):
    			os.remove(f)
    			print("[#] Cleanup, removed " + f)


if __name__ == '__main__':
    unittest.main()
