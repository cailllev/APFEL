# OWN - File Encription
## Description
Uses RSA Algorithm to encript files. No private key is needed tho, only a password. The password is transformed to the next prime number, this is then used as the secret.

## Usage
- create_rsa.py to init numbers for the RSA Algorithm, must be in the same folder as the file to encript / decript
- encript.py to encript a file with given paramfile
- decript.py to decript a file with given paramfile and password

## TODO
- is Python really to slow (removing the JVM part)?
- check security, is this really secure?
- enhance usage, so that command line params can be used
- enhance usage, so that the paramfile does not have to be in same dir
