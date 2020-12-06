import sys

from utility import string_to_number
from utility import keyfile_name
from utility import java_mod_pow


def encript(n, e, p):
    return java_mod_pow(n, e, p)


file_name_to_encode = input("Please enter file's name to encode: ")
file_name_encoded = "encoded_" + file_name_to_encode

keyfile = open(keyfile_name(), "r")
n = int(keyfile.readline())
e = int(keyfile.readline())
keyfile.close()

if n is None or e is None:
    raise Exception("Could not read n or e from file: " + keyfile_name())

file_to_encode = open(file_name_to_encode, "r")
plain = file_to_encode.readlines()
plain_as_num = string_to_number(plain)
file_to_encode.close()

cypher = encript(n, e, plain_as_num)

file_encoded = open(file_name_encoded, "w")
file_encoded.write(str(cypher))
file_encoded.close()

print("File " + file_name_to_encode + " is now encoded -> " + file_name_encoded)
