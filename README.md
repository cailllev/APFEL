# OWN - File Encription
## Description
Uses RSA Algorithm to encript files. No private key is needed tho, only a password. The password is transformed to a bigger (prime) number, this is then used as the decriptor (d).

## Usage
```python3 file_encriptor.py -h```
- ```-i``` or ```--init``` to create a keyfile with given name
- ```-k``` or ```--keyfile``` name of the keyfile, contains ```(n,e,diff)```
- ```-e``` or ```--encript``` to encript a file with given name
- ```-d``` or ```--decript``` to decript a file with given name
- ```-v``` or ```--verbose``` to print the decripted file
- ```-s``` or ```--save``` to save the decripted file

## Threat Modelling
- no obvious weakness, see [here](Threat_Modelling.md)

## TODO
- this project, but with Elliptic Curves instead RSA
- translate this to C or Java, everything is so slow in python

## Implementation Comments
- pow() and "squarre-and-mul-pow()", i.e. my_pow() are almost equally slow (max 1% diff) -> use standard pow()
- ZZ(p).is_prime() is about 2 to 3 times faster and more stable than my_is_prime() -> use ZZ(p).is_prime()
