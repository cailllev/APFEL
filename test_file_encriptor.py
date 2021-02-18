import os
import secrets
import string
import unittest

from random import choice
from sage.all import is_prime

from file_encriptor import *
from utils import *


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
        n_all, e, _ = k.readlines()[1:-1]
        k.close()

        n_all = n_all.strip()
        n, _ = n_all.split(":")
        n = n.strip()
        e = int(e.strip())

        self.assertTrue(n_bit_len + 1 >= int(n).bit_length())
        self.assertTrue(int(n).bit_length() >= n_bit_len)

        self.assertEqual(n_all, str(n_out) + ":" + str(n_bit_len))
        self.assertEqual(e, e_out)

    def test_safe_prime(self):
        n_len = 512
        delta = 9
        p_length_bit = n_len // 2 + delta
        q_length_bit = n_len - p_length_bit

        print("*******************************************************")
        safe_prime_bm(n_len, 2)
        print("*******************************************************")

        start = time.time()
        p = safe_prime(p_length_bit)
        q = safe_prime(q_length_bit)
        dur = round(time.time() - start)

        print(str(dur) + " seconds to create 2 primes for " + str(n_len) + " bit RSA")
        print("*******************************************************")

        self.assertTrue(ZZ(p).is_prime())
        self.assertTrue(ZZ(q).is_prime())
        self.assertTrue(ZZ((p-1)//2).is_prime())
        self.assertTrue(ZZ((q-1)//2).is_prime())

    def test_convert(self):
        n_bit_len = 8

        s = b"A"
        i = ["41"]
        self.assertEqual(bytes_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_bytes(i, n_bit_len), s)

        s = b"AA"
        i = ["41", "41"]
        self.assertEqual(bytes_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_bytes(i, n_bit_len), s)

        s = b"AABBCC"
        i = ["41", "41", "42", "42", "43", "43"]

        self.assertEqual(bytes_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_bytes(i, n_bit_len), s)

        n_bit_len = 16
        s = b"AABBCCDD"
        i = ["4141", "4242", "4343", "4444"]

        self.assertEqual(bytes_to_hex_nums(s, n_bit_len), i)
        self.assertEqual(hex_nums_to_bytes(i, n_bit_len), s)
 
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
	    		bytes_in = b"P"*(i+1)  # P = 0x50
	    		as_hex_nums = bytes_to_hex_nums(bytes_in, n_len)
	    		
	    		self.assertEqual(len(as_hex_nums), j+1)

	    		self.assertEqual(len(as_hex_nums[-1]), block_size)
	    		self.assertEqual(as_hex_nums[-1].count("50"), 1 + i % chars_in_block)
	    		self.assertEqual(as_hex_nums[-1].count("0"), block_size - 1 - (i % chars_in_block))

	    		bytes_out = hex_nums_to_bytes(as_hex_nums, n_len)
	    		self.assertEqual(bytes_in, bytes_out)

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

    def test_encript_and_decript_non_ascii(self):
        create_keyfile(n_len=512, hash_rounds=12)

        f = open(test_file_to_encript, "wb")
        contents = []
        for i in range(1, 256):
            contents.append(i)

        contents = bytearray(contents)

        f.write(contents)
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

        f = open(test_file_to_encript, "rb")
        read = b"".join(f.readlines())
        f.close()

        self.assertEqual(contents, read)

        try:
            os.remove(test_file_to_encript)
        except:
            pass

    def test_encript_and_decript_multiple_blocks(self):
        n_len = 128
        create_keyfile(n_len, 4)

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


    # UNUSED TESTS
    def my_pow_test(self):
        """
        don't test this, own implemenation is as slow as pow
        """
        for x in range(1,20):
            for e in range(1,20):
                for m in range(2,20):
                    self.assertEqual(my_pow(x,e,m), pow(x,e,m))

        x = random.randint(2**2047, 2**2048)
        e = random.randint(2**2047, 2**2048)
        m = random.randint(2**2048, 2**2049)

        self.assertEqual(my_pow(x,e,m), pow(x,e,m))

        my_total = 0
        pow_total = 0
        for i in range(100):
            start = time.time()
            my_pow(x,e,m)
            my_total += (time.time() - start)

            start = time.time()
            my_pow(x,e,m)
            pow_total += (time.time() - start)

        print("***********************")
        print("Normal pow time: " + str(round(pow_total, 3)) + "s")
        print("My pow time:     " + str(round(my_total, 3)) + "s")
        print("***********************")

        # self.assertTrue(my_total <= pow_total)

    def my_is_prime_test(self):
        """
        don't test this, own implemenation is way slower and instable
        """
        bit_length = 2048

        for i in range(1000):
            p = secrets.randbelow(2 ** (bit_length + 1))
            self.assertEqual(ZZ(p).is_prime(), my_is_prime(p))

        my_total = 0
        ZZ_total = 0
        for i in range(2**18):
            start = time.time()
            my_is_prime(p)
            my_total += (time.time() - start)

            start = time.time()
            ZZ(p).is_prime()
            ZZ_total += (time.time() - start)

        print("************************")
        print("ZZ is prime time: " + str(round(ZZ_total, 3)) + "s")
        print("My is prime time: " + str(round(my_total, 3)) + "s")
        print("************************")

        # self.assertTrue(my_total <= ZZ_total)


if __name__ == '__main__':
    unittest.main()
