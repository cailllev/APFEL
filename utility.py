import math

from jpype import *

base = 128  # ASCII


def java_mod_pow(mod, exp, base):
    mod_string = str(mod)
    exp_string = str(exp)
    base_string = str(base)

    startJVM("C:\\Program Files\\Java\\jdk-11\\bin\\server\\jvm.dll", "-ea")

    math_package = JPackage("java.math")
    bigint_class = math_package.BigInteger

    mod_bigint = bigint_class(mod_string)
    exp_bigint = bigint_class(exp_string)
    base_bigint = bigint_class(base_string)

    res = (base_bigint.modPow(exp_bigint, mod_bigint)).toString()

    shutdownJVM()
    return res


def java_next_prime(val):
    val_string = str(val)

    startJVM("C:\\Program Files\\Java\\jdk-11\\bin\\server\\jvm.dll", "-ea")

    math_package = JPackage("java.math")
    bigint_class = math_package.BigInteger

    val_bigint = bigint_class(val_string)

    res = (val_bigint.nextProbablePrime()).toString()

    shutdownJVM()
    return res


def keyfile_name():
    return "rsa_pub"


def string_to_number(string_list):
    total_length = 0
    for string in string_list:
        total_length += len(string)

    res = 0
    mag = total_length - 1
    for string in string_list:
        for s in string:
            res += ord(s) * math.pow(base, mag)
            mag -= 1

    return int(res)


def number_to_string(num):
    if num != int(num):
        raise Exception("Only integers allowed: ", num)

    char_vals = []
    while num > 0:
        divisor = num // base
        remainder = int(num % base)

        char_vals.append(chr(remainder))

        num = divisor

    char_vals.reverse()
    return ''.join(char_vals)