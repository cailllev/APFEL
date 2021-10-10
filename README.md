# Asymmetric Password File Encryption Library
## Description
Uses the RSA / ECC / El Gamal algorithm to encrypt files. Only a password is needed, i.e. no private key (files) meaning that *all* files can be public. The password is transformed to a (prime) number to be used as the secret.

## Usage
```
init:    python3 apfel.py -i <keyfile>
            i: the name of the new keyfile

encrypt: python3 apfel.py -k <keyfile> -e <file to encrypt> [-a RSA | ECC | EG] [-r]
            k: the keyfile with the keys
            e: the file to encrypt
            a: algorithm to encrypt, defaults to all
            r: remove original after encryption
            
decrypt: python3 apfel.py -k <keyfile> -d <file to decrypt> [-v] [-s <new file name>]
            k: the keyfile with the keys
            d: the file to decrypt
            v: verbose, print decrypted file
            s: save decrypted file
```

## Threat Modelling
- no obvious RSA weakness, see [here](Threat_Modelling.md)

## TODO
- add ECC and El Gamal encryption algorithm
- update threat modelling
- create pypi package
- read https://www.researchgate.net/profile/Anton-Stiglic-2/publication/2372902_Security_Issues_in_the_Diffie-Hellman_Key_Agreement_Protocol/links/54b55eea0cf28ebe92e53305/Security-Issues-in-the-Diffie-Hellman-Key-Agreement-Protocol.pdf?origin=publication_detail

## Implementation Comments
- own RSA used instead of Pycryptodome's bc. they need a private key or a PEM cert -> destroying the "all files can be public" part
-  
