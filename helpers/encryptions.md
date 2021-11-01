# RSA: multiplicative Groups
| var | equation |  comments |
|---|---|---|
| p	| | is prime and secret |
| q	| | is prime and secret |
| n | = p * q	| is public |
| phi | = (p-1) * (q-1)	| size of multiplicative group Zn* |
| e 	| = 65537	| is public (most of the time 65537, just has to be relative prime to phi) |
| d 	| = e^-1 % n	| is private, d is so that d * e % phi = 1 (otherwise RSA wouldn't work) |

## Encription & Decription => Confidentiality:
| var | equation |  comments |
|---|---|---|
| m | | the plain text to encrypt |
| c |= m**e % n | ciphertext |
| m |= c**d % n | the plaintext again |

### Math:
```
m = c**d % n      	-> extend c, i.e. c = m**e
 => (m**e)**d % n 	-> rewrite
 => m**(e*d) % n  	-> e*d % n = 1
 => m**(1) % n    	-> m**1 == m
 => m
-> everyone can create ciphers with your public key (n,e)
-> only you can decript it, only you know d
```

## Sign and Check => Authenticity:
| var | equation |  comments |
|---|---|---|
| h() | | any safe hash function |
| s | = h(m)**d % n | create the signature of hashed m |

signature is valid when:
```
h(m) == s**e % n
```

### Math:
```
s**e % n               	-> extend s
 => (h(m)**d)**e % n   	-> rewrite exponent
 => (h(m)**(d**e) % n  	-> same as above
 => h(m)**1 % n
-> everyone can check your signature with public key (n,e)
-> no one can create it, only you know d
-> safe bc difficult to factor large numbers (n)
```
 

# El Gamal & Diffie Hellman (discrete logarithm)
| var | equation |  comments |
|---|---|---|
| p | | the modulus, is prime and part of public key |
| g | | the generator, is random and part of public key |

## Encription & Decription => Confidentiality:
### Algorithm
#### Alice's init
| var | equation |  comments |
|---|---|---|
| a | | her key,	random chosen and private |
| A | =	g**a % p	|	part of public key |
 => Alice sends Bob (p,g,A)

#### Bob's init
| var | equation |  comments |
|---|---|---|
| m || the plain text to encrypt |
| b || his key, random chosen and private |
| B | =	g**b % p	|	part of public key |
| c | =	A**b * m % p	|	cipher of m |
 => Bob sends Alice (B,c)

#### Alice's decryption
```m =	c * B**(p-1-a) % p	-> plain again```

### Math:
```m = c * B**(p-1-a) % p 
 => (A**b * m % p) * B**(p-1-a) % p 	-> extend c, i.e. c = (A**b * m % p)
 => m * A**b * B**(p-1-a) % p			-> rewrite, take m to front
 => m * A**b * B**(p-1) * B**(-a) % p	-> rewrite, B**(p-1-a) == B**(p-1) * B**(-a)
 => m * A**b * B**(-a) % p				-> B**(p-1) == 1 (Fermat's Little Theorem)
 => m * (g**a)**b * (g**b)**(-a) % p	-> rewrite, insert vars for A and B
 => m * g**ab * g**-ab % p				-> g**ab * g**-ab => g**ab / g**ab => 1
 => m * 1 % p
 => m
-> everyone can create ciphers
-> only you can decript it because only you know a
-> safe bc difficult to find log_base_g(a) % p, i.e. difficult to find x when g**x % p == a
```

## Sign and Check => Authenticity:
| var | equation |  comments |
|---|---|---|
| h()	| |	any safe hash function |
| k | = [2 ... p-2] |	random number, just has to be relative prime to (p-1) |
| r | = g**k % p | part 1 of signature |
| s | = (h(m) - a*r)*k^-1 % (p-1)	| part 2 of signature |

signature is valid when:
```
g**h(m) == A**r * r**s % p
```

### Math:
```h(m) = a*r + s*k % (p-1)				-> rewrite from above, s = (h(m) - a*r)*k^-1 % (p-1)
 => g**h(m) = g**(a*r + s*k) % p		-> both sides g**(...)
 => g**h(m) = g**a**r * g**(s*k) % p	-> expand parentheses
 => g**h(m) = A**r * r**s % p			-> rewrite g**a => A and g**(s*k) => r**s, bc r == g**k
 => same as above
-> everyone can check your signature with your public key (p,g,A)
-> no one can create it because only you know a
```
 
*************************************************************************************************************
El Gamal & Diffie Hellman (ECC)
*******************************
| var | equation |  comments |
|---|---|---|
| E | = {y^2 = x^3 + ax + b} | 		the set of points to use for encription (comparable to Zn*)
| p | |  is prime, the "modulus" of the curve E
| E | = EllipticCurve(GF(p),[a,b]) | the curve E

### Algorithm
#### Alice's init
| var | equation |  comments |
|---|---|---|
| kA | |  the key, random chosen, private and < n
| P | | Point on E, part of public key
| n | | order of P, how many times P+P+P... is valid, must be a prime, this is now the "modulus"
| A | = kA * P | part of public key, automatically another Point on E (bc. kA < n)

 => Alice sends Bob = (E,p,P,A)

#### Bob's init
| var | equation |  comments |
|---|---|---|
| m | | the plain text to encrypt, smaller than n | 
| M | = m << 8 + x | the plain text, but it is on the curve | 
| x | = [0...2^8] | some offset, so the m is on the curve (element of E) | 
| kB | | the key, random chosen and private | 
| B | = kB * P | part of public key | 
| C | = M + kB * A | cipher of M | 

 => Bob sends Alice (B,C)

#### Alice's decryption
```
M =	-kA * B + C
m = M >> 8
```

### Math:
```
Alice wants to decrypt Bob's C and knows Bobs B

show that "kA * B == kB * A":
A = kA * P
B = kB * P
kA * B => kA * kB * P 	(Alice does still not know kB, only B)
kB * A => kB * kA * P 	(Bob does still not know kA, only A)
it follows -> kA * B == kB * A

now decrypt:
C = M + kB * A			normal decryption, why does it work now?
M = C - kB * A			"refactor" equation
M = C - kA * B			from the point that "kA * B == kB * A"
`` 

