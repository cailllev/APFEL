# Threat Modelling for PARSA Project
This document's purpose is to show if PARSA is safe to use or not.
The potential vulnerabilities are listed below, followed by their aversion.

## Potential Attacks
### Attack on d (decriptor)
 - exploit
   - reverse engineer process of d's creation
 - countermeasure
   - bcrypt hash is used, not reverable
   - plus, any guessing takes long b.c. 2^16 rounds are used
   => reversing fails

 - exploit 
   - dictionary attack on d
 - countermeasure
   - enforce stong passwords
   => dictionary attack should fail -> at least as safe as other passwords

 - exploit 
   - precompiled hash attack on d
 - countermeasure
   - use random salt
   => precompiled attack fails

 - exploit 
   - guess the d, bc it is known to be a prime
 - countermeasure
   - there are (x / ln(x)) primes up to integer x
   - d is in range n_bits-17 ... n_bits-1
   - assuming n is 2048 (considered safe) -> d = 2^2047 - 2^2031 = 2^2046.99998 => 2^2047
   - number of primes that d could be ≃ 2^2047 / ln(2^2047) = 2^2037
   - this is not feasable
   => guessing d fails

 - exploit
   - physically see someone typing in their password
 - countermeasure
   - getpass() is used
   - password only visible via keyboard, not via bash history or on monitor
   => as good as possibly prevented -> at least as safe as other passwords

### Attack on e (encriptor)
 - exploit
   - small exponent attack
 - countermeasure
   - e is generated according to d
   - immensly small chance to be small
   - e.g. if e were to be smaller than 2^4, 1 in (2^2048 - 2^4) = 1 in 2^2048
   - logic implemented nevertheless
   => small exponent attack fails

 - exploit
   - chinese remainder theorem attack (record e messages to reverse rsa)
 - countermeasure
   - see above
   => crt attack fails

 - exploit
   - small plaintext attack
 - countermeasures
   - all plaintext is padded to block size (i.e. n)
   => small plaintext attack fails

### Attack on n (modulus)
 - exploit 
   - find factors of n (unsafe generation primes p & q)
 - countermeasures
   - use safe primes, (p-1)/2 is still a prime
   - enforce large n
   => finding factors fails

 - exploit 
   - find factors of small n
 - countermeasures
   - enforce large n
   => finding factors fails

### Attack on keyfile
 - exploit 
   - sensitive information disclosure in keyfile
 - countermeasures
   - no private keyfile
   - public keyfile contains no sensitive information
   => no attack possible

### Attack on encripted file
 - exploit 
   - reverse engineer data in encripted files
 - countermeasures
   - rsa algorithm is considered to be secure
   => no attack possible

 - exploit
   - delete keyfile, no more decripting possible
 - countermeasures
   - none, same as with normal rsa