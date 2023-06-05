from Math_crypto import invmod, Egcd, fastpower, get_BigPrime
import hashlib
import random
class RSA:
    def __init__(self, e_or_d, N):
        self.e_or_d = e_or_d
        self.n = N
        print('if you want to do RSA encryption or decryption, these two params you input when create class is e_or_d and N')
        print('but if want to generate RSA key, these two params is meaningless to you and you should continue to enter the required parameters in the next step')

    def help(self):
        print('my loader if you wanna generate RSA key, you should use the following function')
        print('   1. keyGenerateGivenBitLength(N) -- N is the bitlength of the p and q')
        print('   2. keyGenerateGiven_Param_pq(p, q) -- p and q are two primes')
        print('if you wanna do RSA encryption or decryption, you should use the following function')
        print('   1. encrypt(m) -- m is the plaintext, and the return value is the ciphertext')
        print('       what should be noted is that the plaintext should be a number, not a string')
        print('   2. decrypt(c) -- c is the ciphertext, and the return value is the plaintext')
        print('       what should be noted is that the ciphertext should be a number, not a string')
        print('if you wanna do OAEP encryption or decryption, you should use the following function')
        print('   1. OAEP_Encryption(m, L) -- m is the plaintext, L is the label')
        print('       what should be noted is that the plaintext should be a hex number, not a string so do the other params')
        print('   2. OAEP_Decryption(c, L) -- c is the ciphertext, L is the label')
        print('       what should be noted is that the ciphertext should be a hex number, not a string so do the other params')
        print('Thank you for your support!')

    def keyGenerateGiven_Param_pq(self, p, q):
        self.n = p * q
        self.phi_n = (p - 1) * (q - 1)
        e = random.choice([3, 17, 65537])  # 或者选择其他质数

        while True:
            if self.phi_n % e == 0:
                e += 2
            else:
                break
        self.e = e
        self.d = invmod(self.e, self.phi_n)
        return self.e, self.n

    def keyGenerateGivenBitLength(self, N):
        """
        :param N: bitlength of the p and q
        :return: public key : (e, n)
        """
        self.p = get_BigPrime(N)
        self.q = get_BigPrime(N)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        e = random.choice([3, 17, 65537])  # 或者选择其他质数

        while True:
            if self.phi_n % e == 0:
                e += 2
            else:
                break
        self.e = e
        self.d = invmod(self.e, self.phi_n)
        self.p = self.q = self.phi_n = None
        return self.e, self.n

    def encrypt(self, m):
        self.e = self.e_or_d
        return fastpower(m, self.e, self.n)

    def decrypt(self, c):
        self.d = self.e_or_d
        return fastpower(c, self.d, self.n)

    def LengthTest(self, L_len, mLen, k, hLen):
        if L_len >= 2 ** 61:
            raise ValueError('Label too long LengthTest 1')
        elif mLen > k - 2 * hLen - 2:
            raise ValueError('Message too long LengthTest 2')

    def get_L_hash(self, L):
        L = L[2:]
        if L == '':
            return hashlib.sha1(bytearray.fromhex(L)).hexdigest()
        # 对l进行填充，使得满足8的倍数
        if len(L) % 2 != 0:
            L = '0' + L
        return hashlib.sha1(bytearray.fromhex(L)).hexdigest()

    def MGF(self, mgfSeed, maskLen):
        """
        :param mgfSeed: str, starting with 0x, representing plaintext; firstly should remove 0x
        :param maskLen: int, the length of the mask
        :return: str, starting with 0x, representing plaintext; firstly should remove 0x
        """
        mgfSeed = mgfSeed[2:]
        hLen = 20
        if len(mgfSeed) % 2 != 0:
            mgfSeed = '0' + mgfSeed
        T = bytearray(b'')
        X = bytearray.fromhex(mgfSeed)
        counter = 0
        temp = X + bytearray.fromhex('00000000')
        T = T + bytearray.fromhex(hashlib.sha1(temp).hexdigest())
        HMlen = len(T.hex()) // 2
        counter += 1

        if maskLen == HMlen:
            return T.hex()
        else:
            tlen = T.__len__() // 2
            while tlen < maskLen:
                tmp = X + bytearray.fromhex('%08x' % counter)
                T = T + bytearray.fromhex(hashlib.sha1(tmp).hexdigest())
                tlen = T.hex().__len__() // 2
                counter += 1
            return T.hex()[:maskLen * 2]

    def EME_OAEP(self, L, hLen, k, mLen, msg, seed):
        """
        :param L:
        :param hLen:
        :param k:
        :param mLen:
        :param msg: str, starting with 0x, representing plaintext; firstly should remove 0x
        :param seed:
        :return: 勿忘六四，打倒共党，自由民主，人权万岁
        """

        lHASH = self.get_L_hash(L)
        PSLen = k - mLen - 2 * hLen - 2
        PS = ''
        for i in range(PSLen):
            PS += '00'
        DB = lHASH + PS + '01' + msg[2:]
        l = k - hLen - 1
        seed = seed[2:]
        for i in range(hLen - seed.__len__()):
            seed = '0' + seed
        dbMask = self.MGF('0x' + seed, l)
        temp_DB = int(DB, 16)
        temp_dbMask = int(dbMask, 16)
        maskedDB = temp_DB ^ temp_dbMask
        maskedDB = hex(maskedDB)[2:]
        for i in range(2 * l - maskedDB.__len__()):
            maskedDB = '0' + maskedDB
        maskedDB = '0x' + maskedDB
        seedMask = self.MGF(maskedDB, hLen)
        maskedDB = maskedDB[2:]
        # # print(type(seed))
        # print(seedMask)
        temp_seedMask = int(seedMask, 16)
        temp_seed = int(seed, 16)
        maskedSeed = temp_seed ^ temp_seedMask
        maskedSeed = hex(maskedSeed)[2:]
        for i in range(2 * hLen - maskedSeed.__len__()):
            maskedSeed = '0' + maskedSeed
        # print('maskedSeed=',maskedSeed)
        EM = '00' + maskedSeed + maskedDB
        return EM

    def OAEP_encryption(self, k, m, L, seed):
        """
        :param k: An integer k, representing the security parameter of the RSA algorithm (such as k=1024 / 8 = 128 given for RSA-1024)
        :param m: A hexadecimal number, starting with 0x, representing plaintext; the length does not exceed k - 2hLen - 2
        :param L: A hexadecimal number, starting with 0x, representing the label; the length does not exceed 2^61 - 1
        :param seed: A hexadecimal number, starting with 0x, representing a random number; the length is hLen
        :return: A hexadecimal number, starting with 0x, representing ciphertext
        """
        L_len = (len(L) - 2) // 2
        hLen = 20
        mLen = (len(m) - 2) // 2
        self.LengthTest(L_len, mLen, k, hLen)
        EM = self.EME_OAEP(L, hLen, k, mLen, m, seed)
        if EM == False:
            raise ValueError('Encoding error OAEP_encryptin 1')
        m = int(EM, 16)
        e = self.e_or_d
        res = hex(self.encrypt(m))[2:]
        for i in range(2 * k - res.__len__()):
            res = '0' + res
        return '0x' + res

    def LengthTest_Decryption(self, L_len, k, hLen, M):
        if L_len >= 2 ** 61:
            raise ValueError('Label too long LengthTest_Decryption 2')
        if M.__len__() % 8 != 0:
            raise ValueError('Decryption error LengthTest_Decryption 1')
        if k < 2 * hLen + 2:
            raise ValueError('Decryption error LengthTest_Decryption 3')
        # return 1
    def EME_OAEP_decode(self, L, hLen, k, EM):
        lHASH = self.get_L_hash(L)
        Y = EM[0: 2]
        maskedSeed = EM[2: 2 * hLen + 2]
        maskedDB = EM[2 * hLen + 2:]
        seedMask = self.MGF('0x' + maskedDB, hLen)
        temp_seedMask = int(seedMask, 16)
        temp_maskedSeed = int(maskedSeed, 16)
        seed = temp_maskedSeed ^ temp_seedMask
        seed = hex(seed)[2:]
        if 2 * hLen > seed.__len__():
            for i in range(2 * hLen - seed.__len__()):
                seed = '0' + seed
        dbMask = self.MGF('0x' + seed, k - hLen - 1)
        temp_dbMask = int(dbMask, 16)
        temp_maskedDB = int(maskedDB, 16)
        DB = temp_maskedDB ^ temp_dbMask
        DB = hex(DB)[2:]
        if 2 * (k - hLen - 1) > DB.__len__():
            for i in range(2 * (k - hLen - 1) - DB.__len__()):
                DB = '0' + DB
        lHASH_ = DB[0: 2 * hLen]
        if lHASH != lHASH_:
            raise ValueError('Decryption error HASH value does not match')
        index = DB.find('01', 2 * hLen, len(DB))
        if index == -1:
            raise ValueError('Decryption error 0x01 does not exist')
        M = DB[index + 2:]
        return M

    def OAEP_decryption(self, k, c, L):
        """
        :param k:
        :param c: A hexadecimal number, starting with 0x, representing ciphertext; the length does not exceed k - 2hLen - 2
        :param L:
        :return: A hexadecimal number, starting with 0x, representing plaintext
        """
        L_len = (len(L) - 2) // 2
        hLen = 20
        cLen = (len(c) - 2) // 2
        self.LengthTest_Decryption(L_len, k, hLen, c[2:])
        C = int(c, 16)
        if C >= self.n:
            raise ValueError('parameter \'ciphertext\' error')
        m = self.decrypt(C)
        EM = hex(m)[2:]
        EMLen = EM.__len__()
        if EMLen > 2 * (k - 1):
            raise ValueError('Decryption error EMLen > 2 * (k - 1)')
        for i in range(2 * (k - 1) - EM.__len__()):
            EM = '0' + EM
        EM = '00' + EM
        if EM.__len__() != 2 * k:
            raise ValueError('Decrypting Length error EM.__len__() != 2 * k')
        M = self.EME_OAEP_decode(L, hLen, k, EM)
        M = int(M, 16)
        return hex(M)[2:]



