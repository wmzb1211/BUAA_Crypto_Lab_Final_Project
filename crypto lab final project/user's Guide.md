# user's Guide

---

## 1. Introduction

​	This is a an user's Guide of my Crypto Library. In this article, there are some introductions and precautions about how to use this Algorithm library, for example, I will show you what you should input and what you may get from output.

## 2. Illustration

### 1)Math_Crypto.py

​	Firstly, you should to import ``Math_Crypto.py`` ,then you can use any functions in this file. What have to be aware of is that if you wanna use the function: fastpower, you need to understand the meaning of these three parameters: calculate $a ^ b \% c$.

​	*This part is not object-oriented.*

```python
import Math_Crypto.py
a = 6
b = 7
c = 8
print(fastpower(a, b, c))
# the result is 0
```

### 2)SM2.py

​	**SM2 is a digital signature function.** There are two functions: sign and verify.

​	 Whatever you want to do, first create an object.

```python
from SM2 import SM2
sm2 = SM2(a, b, p, G, n)
```

***five init parameters: a, b, p, G, n
a, b, p are parameters of the elliptic curve
G is the base point of the elliptic curve
n is the order of the base point***

```python
result = sm2.sign(SM2_sign_ID_A, SM2_sign_P_A, SM2_sign_M, SM2_sign_d_A, SM2_sign_k)
```

**the parameters of sign() you should input are:ID_A, P_A, M, d_A, k
    ID_A: the ID of the signer (a string)
    P_A: the public key of the signer (a point on the elliptic curve)
    M: the message you wanna sign (a string)
    d_A: the private key of the signer (a number)
    k: a random number (a number)**

**return: Signature of A (bytes type)**

Steps to use Veriry function is the same as sign function.

```python
result = sm2.verify(SM2_verify_ID_A, SM2_verify_P_A, SM2_verify_M, SM2_verify_r, SM2_verify_s)
```

**the parameters of verify() you should input are:ID_A, P_A, M, r, s
    ID_A: the ID of the signer (a string)
    P_A: the public key of the signer (a point on the elliptic curve)
    M: the message you wanna check signature (a bytes)
    r: the first part of the signature (a number)
    s: the second part of the signature (a number)**

**return: True if the signature is valid, False otherwise**



### 3)SM3.py

​	First thing is to create an objection.

```python
sm3 = SM3()
```

​	you dont need to input any inital parameters. Just pass parameters to this objection has been created .

```
result = sm3.hash_sm3(SM3_MSG)
```

**the parameters of hash() you should input are: msg
	msg: the message you wanna hash (a string or bytes)**

### 4)SM4.py

​	Whatever you want to do, first thing you should do is to create an objection.

```python
sm4 = SM4(key)
```

​	**The parameter 'key' a hexadecimal number starting with '0x', the length is 34.**

#### i.simply encryption or decryption

 **if you just want to simply encrypt/decrypt, please input: SM4_encrypt/SM4_decrypt
the parameter is: SM4_encrypt/SM4_decrypt [plaintext/ciphertext]**

```python
result = sm4.SM4_encrypt(SM4_plain)
```

​	**plain_text  or  ciphertext: 128bit int**

#### ii. CTR mode

**if you want to use CTR mode, please input: SM4_CTR(file_path, IV, mode)
	the parameter is: SM4_CTR [file_path] [IV] [mode]
	mode is 0 or 1, 0 means encrypt, 1 means decrypt
	IV is a 16 bytes hex format string, like 0x0123456789abcdef, it is the initial vector
	file_path is the file you want to encrypt/decrypt**

==**If you use encryption mode, program will return a new file created in current folder and its name will be file_path + '.SM4_CTR'. And if you use decryption mode, program will return a new file created in current folder and its name will be file_path without '.SM4_CTR' **==

Example:

```python
# encryption mode
file_path_SM4CTR = 'test data/SM4 CTR data.txt'
SM4_encryption_CTR_key = '0x557cfb9c1c78b048ae02bf5c88bc781a'
IV_SM4_CTR = 0xb5e6886305720c08aed644c3dfc36cd4
sm4 = SM4(SM4_encryption_CTR_key)
result = sm4.SM4_CTR(file_path_SM4CTR, IV_SM4_CTR, 1)

# decryption mode
file_path_SM4CTR = 'test data/SM4 CTR data.txt..SM4_CTR'
SM4_encryption_CTR_key = '0x557cfb9c1c78b048ae02bf5c88bc781a'
IV_SM4_CTR = 0xb5e6886305720c08aed644c3dfc36cd4
sm4 = SM4(SM4_encryption_CTR_key)
result = sm4.SM4_CTR(file_path_SM4CTR, IV_SM4_CTR, 0)
```

#### iii.CFB mode

**the parameter is: SM4_CFB [file_path] [IV] [mode]
	mode is 0 or 1, 0 means encrypt, 1 means decrypt')
	IV is a 16 bytes hex format string, like 0x0123456789abcdef, it is the initial vector
	file_path is the file you want to encrypt/decrypt**

==**If you use encryption mode, program will return a new file created in current folder and its name will be file_path + '.SM4_CFB'. And if you use decryption mode, program will return a new file created in current folder and its name will be file_path without '.SM4_CFB' **==

Example:

```python
# encryption mode
file_path_SM4CFB = 'test data/SM4 CFB data.txt'
SM4_encryption_CFB_key = '0x04ab5f1f059edc1d283fb746004847d2'
IV_SM4_CFB = '0xcfd5e738c3887d647181484813ebf90e'
sm4 = SM4(SM4_encryption_CFB_key)
result = sm4.SM4_CFB(file_path_SM4CFB, IV_SM4_CFB, 7, 1)

# decryption mode
file_path_SM4CFB = 'test data/SM4 CFB data.txt.SM4_CFB'
SM4_encryption_CFB_key = '0x04ab5f1f059edc1d283fb746004847d2'
IV_SM4_CFB = '0xcfd5e738c3887d647181484813ebf90e'
sm4 = SM4(SM4_encryption_CFB_key)
result = sm4.SM4_CFB(file_path_SM4CFB, IV_SM4_CFB, 7, 0)
```

### 5)RSA.py

​	Whichever you choose, first step is to create an objection.

```python
from RSA import RSA
rsa = RSA(e, N)
```

​	**parameter e is the Decryption Index or Encryption Index. And N is modulus.**

#### i. generate a big prime number

​	you can use keyGenerateGivenBitLength(N). It will return a pair of public keys: e and n.

​	The parameter N is the bitLength of p and q. You should input a number.

#### ii. simple encryption and decryption

==**if you wanna do RSA encryption or decryption, you should use the following function**==
**encrypt(m) -- m is the plaintext, and the return value is the ciphertext
      what should be noted is that the plaintext should be a number, not a string
decrypt(c) -- c is the ciphertext, and the return value is the plaintext
       what should be noted is that the ciphertext should be a number, not a string**

Example:

```python
from RSA import RSA
e = 2920409522402926597627191488120636244538724270022998166981037583694182889745072153997951709132903469153746154058782302049361904975953920415583179235627460458533897822450783730009468017406778947855134635
p = 9084765279459973722703105122578434463570460548446011782795531096631608711386758039869846624407809636935725454210198201714484752683287324692998717028735972189703006864635333180338384765812830167319173319
q = 658095039219456120108212222379832238548414272254622727412601986833530725509567656248224707048870541531999954162212518311318563356943680180726228479575112943778457627584304132525988962784939253169192487
N = p * q
msgRSA = 8267188997198709383102216295528861867050429668709122381362481797742114635297750
rsa = RSA(e, N)
result = rsa.encrypt(msgRSA)
```

#### iii. RSA-OAEP encryption and decryption

==**if you wanna do OAEP encryption or decryption, you should use the following function**==
 **OAEP_Encryption(m, L) -- m is the plaintext, L is the label
       what should be noted is that the plaintext should be a hex number, not a string so do the other params
 OAEP_Decryption(c, L) -- c is the ciphertext, L is the label
       what should be noted is that the ciphertext should be a hex number, not a string so do the other params**

Example:

```python
# encryption mode
k = 128
NN = 0xc32a1dbd27a8b57617cde48c424ff5936d6415a679a019605deb0f1a4a3b29c73770d77fcb4f3ed36c4f2c94fb17e8c32feb0674b11d340c7734ffc4ca19401b00edca55b34234d6e6459022fe7b318e222b35435aaffcc430990acda67199035118ae140f80fc5b0dafaa3df9f9300a0316340403908278cfe3b9aca2aa6bf1
ee = 0x10001
m = '0xb96af050d20a2f68f1b1b68a90139ff3ef62c2c5527d41122bc6c2bfa59c300dea4791e2e9d9b74518042bc860'
L = '0x'
seed = '0xf72f68a0abb2c333c489800626349e8ea7ecd4da'
rsa = RSA(ee, NN)
result = rsa.OAEP_encryption(k, m, L, seed)

# decryption mode
k = 512
NN = 0xd561ae21b504e8b34f96611a2afea71a927cd2f80a763b6f116d619b1c414f74cf26b50255ef111fdb1a169b3f1388766a36bd9dd42312fe90b1698247e0336b2d73992b1d6f236ceb049e2ebabdbdb66f5bf956fba33dda1ddfeec40f878dd318a254533cb123e62cd22401915e811a0420714b3cb4886734ce5869f754e85a82842e7ce3f8b1ab37ea36b625d4f2370b6cfe93af965562c01e33968dac310b305bd9aadca3a99bd1c6e1b34905762cd434f5a8bc76891e65ecf8b8d22b5803f84795cfa400e8a7da52cafd53f0634fde71b206cbece56785e48da5056b8a6fee4a5df8549f4c85f5c378862e7c339852c25ec76122ab8617f2ce87003be2815d88d5464ab4fda04a63265aa579b3ad434a779ee356470aefcd638469e9e7e07d47f518e32f609976ba2b55230a4c80bb3ff7de65a6fd5b1b6bb454b98e04d7baba9e23c8be59376c96f27c2fddc079a720ecb71508c25ec7af6c89ed1cfbcbf28caaf7d0ea2344d1545967ef0dcd9f83794c57b333eb9fa5f3a1ebf757985289fe9f7286f640d59b8b687cbf1fb8ef194f9279f6684b69d44014ce4dc581d2c4571c94026748d71c6025290885528b1c9842b58a74001022ed8d88082403d2c0379d289c44fe1223041fc7e74ff13e392e8e63a86d0d67397f45d62b3e58d6bbaff9cabe5e748a37fdb6bad47e2245f9d9484c044be0fdce09cf94d89da60f
dd = 0x57c9e74d60df5329aa9dd0f76626fcf316bf9a4088755a4078e80a973949b979f25c176e8d925cf6413b7b7f85b4f098df5c04293204f82499bd140e90a9b21def4637072105ff8a292aee358588d8cb7d07570f2d5a5cf127076181726e2fb060db305c4a850aa3015fb786999b4afc3c2468d82e728c080216bf1361b9a21ad2c5b52696d853a880c9b096c1fbd9674221269ff646a07c8f541d9f5c4c32a54ad10f3d97a711f9d495c177f49bf5a1bdf0c7fd1304a5a74701f6d67b496fddba4121669b2ff088566f67aa4fe57fc6755b4b8636521193c4e7624b396ea43726cf9bd7b6610fa7b194293af3571017243d69a717d49ec2fd895ce4f7f8ab58132cb592101faa79105573603b2785565f44df34a03780d33124f635fd1a6bd3b8cefbcfbbed603b29aa0c777e933c9bccec44dea9b86ccd143234db686dcf4216f3b7b6014e06b9e366423e832c40b6b1f7aac6ec83d8d45ae71ad97b9fc084c386594b50666c6cba1207e6149e848af16296ba674949679e811b0ba899380435aa7226147be8236e1866dd6bd7fefb1c41537111ae1b54c9e30444ae4497b36f13789482bccd3d3ef72f395a20a216ac95b191bcb8a4aec0ac48506155863ae7812287330c90618c09810fc961ef750759b55188859caf43b6bd11d30b38911b2c9b4d9e288d97ffd69de28c560da8d5a09942488c0a2c068200ba0131afe1
c = '0x5cb545b00acadd8a12088ee58da7a25279e6b1b4347c986cee5f0710fe361864376c6e82648121e2e57b40b38f969f47c905211d6cb28fb88aaafcecbf6655b891f70e10d7efa6dca3b58b249ab2aff3d7cf8f2509bcea00f5ba43f9c6124a07fc5e938654d0d70d709b73ab1013a34d969c950e2ebce1279364a0df88a89e74b27fc9f8cfee6423b5b61a3a08aba385991835ff749a7b4098cbb7ca0e0f6a5255f7e3174d9dcfccc6fc8c7e834bbd14f2c58ac33094b277413b84620a5296ca9a2c8486d152ea3fb1025f2d8ec88a467d277650b04166e761649eb833b9083c09c8940a2f6c1981bc0839bbbbc608cb41e72d56671648d9bac0eca47240cd4ccadbd9c100f01913af27457a40dc25dad53c90c297ebb1e7dfcdf7c53cd24cc4f68f034b77f583c8e58892d44113a4a73d565df68fc69e15fbfaec4643d22f14f376ea8f4edc3902aa68f7b39d42c0ba34b6eaaa0872ea1a739a40e26bdf34b58430e159440c672a1a9da48f0f1eb5c328eea541e6bcda9d85eac47f2185616fabc0025f25529b27ac36a880a7cae088942f489627fd2f51c13f5d9713d3d00ae5915da6ac3d611a0bd891103249ebb2e8b5603d7e3ade797fc92378115fadad98b9520370db7b96c0538b191afc82a2928e163b8b0852534f3e5905b547655707695b5b986db502e1737e1c813b76409855bf966f6429d171e31cfa11d733e4'
L = '0x'
rsa = RSA(dd, NN)

result = rsa.OAEP_decryption(k, c, L)
```



- **k**: An integer k, representing the security parameter of the RSA algorithm (such as k=1024 / 8 = 128 given for RSA-1024)
- **m**: A hexadecimal number, starting with 0x, representing plaintext; the length does not exceed k - 2hLen - 2
- **c**:A hexadecimal number, starting with 0x, representing ciphertext; the length does not exceed k - 2hLen - 2
- **L**: A hexadecimal number, starting with 0x, representing the label; the length does not exceed 2^61 - 1
- **seed**: A hexadecimal number, starting with 0x, representing a random number; the length is hLen
- **return**: A hexadecimal number, starting with 0x, representing ciphertext or plaintext

## The End

​	Thank you for using my CryptoLibrary. If possible, please give me a star on **[[Crypto_Lab_Final_Project]](https://github.com/wmzb1211/BUAA_Crypto_Lab_Final_Project)** (GitHub link for this project), thank you very much.

​	==*<u>**By the way, all the usage of functions and classes could be viewed in method: help(). **</u>*==

