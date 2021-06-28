# Asymmetric Password File Encryption Library
## Description
Uses the RSA / ECC / El Gamal algorithm to encrypt files. No private key is needed tho, only a password. The password is transformed to a (prime) number, this is then used as the decriptor / the secret.

## Usage
### Help
```
python3 apfel.py -h
```
```
  -i, --init     to create a keyfile with given name
  -k, --keyfile  name of the keyfile
  -e, --encript  to encript a file with given name
  -d, --decript  to decript a file with given name
  -v, --verbose  to print the decripted file
  -s, --save     to save the decripted file
```

### Init Keyfile
```python3 apfel.py -i <keyfile name>```

### Encrypt File
```python3 apfel.py -k <keyfile name> -e <file to encrypt>```

### Decrypt File
```python3 apfel.py -i <keyfile name> -d <file to decrypt> [-v] [-s]```

## Threat Modelling
- no obvious RSA weakness, see [here](Threat_Modelling.md)

## TODO
- add ECC and El Gamal encryption algorithm -> encryption and decryption must be same algo
- implement with [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/), only the creation of the parameters is own, the algos should be from [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- update threat modelling
- update usage help print
- rename files, correct typos
- create pypi package

## Implementation Comments
- 
