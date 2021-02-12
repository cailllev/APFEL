# Threat Modelling for paRSA Project
This document's purpose is to show if paRSA is safe to use or not. </br>
The potential attacks (i.e. vulnerabilities) are listed below, followed by their prevention.

## Potential Attacks
### Attack on d (decriptor)
 - reverse engineer process of d's creation
   - bcrypt hash is used, not reverable
   - plus, any guessing takes long b.c. 2^16 rounds are used
   - => reversing fails

 - dictionary attack on d
   - enforce stong passwords
   - => dictionary attack should fail -> at least as safe as other passwords

 - precompiled hash attack on d
   - use random salt
   - => precompiled attack fails

 - guess the d, bc it is known to be a prime
   - there are (x / ln(x)) primes up to integer x
   - d is in range n bits - 17 ... n bits - 1
   - assuming n is 2048 (considered safe) -> d = 2^2047 - 2^2031 = 2^2046.99998 => 2^2047
   - number of primes that d could be ≃ 2^2047 / ln(2^2047) = 2^2037
   - this is not feasable
   - => guessing d fails

 - physically see someone typing in their password
   - getpass() is used
   - password only visible via keyboard, not via bash history or on monitor
   - => as good as possibly prevented -> at least as safe as other passwords

### Attack on e (encriptor)
 - small exponent attack
   - e is generated according to d
   - immensly small chance to be small
   - e.g. if e were to be smaller than 2^4, 1 in (2^2048 - 2^4) = 1 in 2^2048
   - logic implemented nevertheless
   - => small exponent attack fails

 - chinese remainder theorem attack (record e messages to reverse rsa)
   - see above, e too big
   - => crt attack fails

 - small plaintext attack
   - all plaintext is padded to block size (i.e. n)
   - => small plaintext attack fails

### Attack on n (modulus)
 - find factors of n (unsafe generation primes p & q)
   - use safe primes, (p-1)/2 is still a prime
   - enforce large n
   - => finding factors fails

 - find factors of small n
   - enforce large n
   - => finding factors fails

### Attack on keyfile
 - sensitive information disclosure in keyfile
   - no private keyfile
   - public keyfile contains no sensitive information
   - => no attack possible

### Attack on encripted file
 - reverse engineer data in encripted files
   - rsa algorithm is considered to be secure
   - => no attack possible

 - delete keyfile, no more decripting possible
   - none, same as with normal rsa, if keyfile gone, you done
   - => as safe as rsa
