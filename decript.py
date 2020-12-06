from utility import keyfile_name
from utility import string_to_number
from utility import number_to_string
from utility import java_mod_pow


def decript(n, d, c):
    return java_mod_pow(n, d, c)


file_name_to_decode = input("Please enter the file's name to decode: ")

private_key_orginal = input("Please enter your password: ")

keyfile_name = keyfile_name()
print('Keyfile name:', keyfile_name)

private_key_orginal = string_to_number(private_key_orginal)

file_to_decode = open(file_name_to_decode, "r")
cypher = int(file_to_decode.readline())
file_to_decode.close()

if cypher is None:
    raise Exception("Cyphertext cannot be null")

keyfile = open(keyfile_name, "r")
n = int(keyfile.readline())
keyfile.readline()  # omits e (not used in decrypt)
diff = int(keyfile.readline())  # read diff to prime (password + diff = d)
keyfile.close()

private_key = private_key_orginal + diff

if n is None:
    raise Exception("n cannot be null")

decripted = int(decript(n, private_key, cypher))

print("**********************************************************")
print("Successfully decripted, file contents:")
print("----------------------------------------------------------")
print(number_to_string(decripted))
print("**********************************************************")
