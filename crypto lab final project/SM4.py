import Math_crypto
import math
import random
class SM4:
    Sbox = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]

    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]

    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    RoundKey = []
    '''
    Above are System Parameters
    '''

    def __init__(self, key):
        if len(key) != 34 and key[0:2] == '0x':
            raise ValueError("Key length must be 16 bytes")
        elif key[0:2] != '0x' and len(key) != 32:
            raise ValueError("Key length must be 16 bytes")
        self.key = int(key, 16)
        self.build_key()

    def help(self):
        print('SM4 encrypt/decrypt, the parameter you should input when create the class SM4 is a 16 bytes key in hex format')
        print("Usage: three modes: simple encrypt/decrypt, CTR mode encrypt/decrypt, CBF mode encrypt/decrypt")
        print('if you just want to simply encrypt/decrypt, please input: SM4_encrypt/SM4_decrypt')
        print('     the parameter is: SM4_encrypt/SM4_decrypt [plaintext/ciphertext]')
        print('if you want to use CTR mode, please input: SM4_CTR(file_path, IV, mode)')
        print('     the parameter is: SM4_CTR [file_path] [IV] [mode]')
        print('     mode is 0 or 1, 0 means encrypt, 1 means decrypt')
        print('     IV is a 16 bytes hex format string, like 0x0123456789abcdef, it is the initial vector')
        print('     file_path is the file you want to encrypt/decrypt')
        print('if you want to use CFB mode, please input: SM4_CFB(file_path, IV, mode)')
        print('     the parameter is: SM4_CFB [file_path] [IV] [mode]')
        print('     mode is 0 or 1, 0 means encrypt, 1 means decrypt')
        print('     IV is a 16 bytes hex format string, like 0x0123456789abcdef, it is the initial vector')
        print('     file_path is the file you want to encrypt/decrypt')
        print('Thanks for using SM4!')

    def build_key(self):
        """
        generate round key
        """
        K = [
            (self.key >> 96 & ((1 << 32) - 1)) ^ self.FK[0], (self.key >> 64 & ((1 << 32) - 1)) ^ self.FK[1],
            (self.key >> 32 & ((1 << 32) - 1)) ^ self.FK[2], (self.key & ((1 << 32) - 1)) ^ self.FK[3]
        ]
        for i in range(32):
            tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ self.CK[i]
            Stmp = self.Sbox[(tmp >> 24) & 255] << 24
            Stmp += self.Sbox[(tmp >> 16) & 255] << 16
            Stmp += self.Sbox[(tmp >> 8) & 255] << 8
            Stmp += self.Sbox[tmp & 255]
            Stmp = (((Stmp & ((1 << 19) - 1)) << 13) + (Stmp >> 19)) ^ Stmp ^ (((Stmp & ((1 << 9) - 1)) << 23) + (Stmp >> 9))
            Stmp ^= K[i]
            self.RoundKey.append(Stmp)
            K.append(Stmp)

    def SM4_encrypt(self, plain_text):
        """
        :param plain_text: 128bit int
        :return: 128bit int
        """
        PLAINTEXT = [(plain_text >> 96 & ((1 << 32) - 1)), (plain_text >> 64 & ((1 << 32) - 1)) , (plain_text >> 32 & ((1 << 32) - 1)), (plain_text & ((1 << 32) - 1))]
        for i in range(32):
            temp = PLAINTEXT[i + 1] ^ PLAINTEXT[i + 2] ^ PLAINTEXT[i + 3] ^ self.RoundKey[i]
            Stmp = self.Sbox[(temp >> 24) & 255] << 24
            Stmp += self.Sbox[(temp >> 16) & 255] << 16
            Stmp += self.Sbox[(temp >> 8) & 255] << 8
            Stmp += self.Sbox[temp & 255]
            Stmp = (((Stmp & ((1 << 30) - 1)) << 2) + (Stmp >> 30)) \
                   ^ (((Stmp & ((1 << 22) - 1)) << 10) + (Stmp >> 22)) \
                   ^ Stmp \
                   ^ (((Stmp & ((1 << 14) - 1)) << 18) + (Stmp >> 14)) \
                   ^ (((Stmp & ((1 << 8) - 1)) << 24) + (Stmp >> 8))\
                   ^ PLAINTEXT[i]
            PLAINTEXT.append(Stmp)
        return (PLAINTEXT[35] << 96) + (PLAINTEXT[34] << 64) + (PLAINTEXT[33] << 32) + PLAINTEXT[32]

    def SM4_decrypt(self, cipher_text):
        """
        :param cipher_text: 128bit int
        :return: 128bit int
        """
        CIPHERTEXT = [(cipher_text >> 96 & ((1 << 32) - 1)), (cipher_text >> 64 & ((1 << 32) - 1)) , (cipher_text >> 32 & ((1 << 32) - 1)), (cipher_text & ((1 << 32) - 1))]
        for i in range(32):
            temp = CIPHERTEXT[i + 1] ^ CIPHERTEXT[i + 2] ^ CIPHERTEXT[i + 3] ^ self.RoundKey[31 - i]
            Stmp = self.Sbox[(temp >> 24) & 255] << 24
            Stmp += self.Sbox[(temp >> 16) & 255] << 16
            Stmp += self.Sbox[(temp >> 8) & 255] << 8
            Stmp += self.Sbox[temp & 255]
            Stmp = (((Stmp & ((1 << 30) - 1)) << 2) + (Stmp >> 30)) \
                   ^ (((Stmp & ((1 << 22) - 1)) << 10) + (Stmp >> 22)) \
                   ^ Stmp \
                   ^ (((Stmp & ((1 << 14) - 1)) << 18) + (Stmp >> 14)) \
                   ^ (((Stmp & ((1 << 8) - 1)) << 24) + (Stmp >> 8))\
                   ^ CIPHERTEXT[i]
            CIPHERTEXT.append(Stmp)
        return (CIPHERTEXT[35] << 96) + (CIPHERTEXT[34] << 64) + (CIPHERTEXT[33] << 32) + CIPHERTEXT[32]

    def CTR_get_key(self, IV, l):
        res = []
        for i in range(l):
            res.append(self.SM4_encrypt(IV + i))
        return res


    def SM4_CTR(self, file_path, IV, MODE):
        """
        :param file_path: path of file
        :param IV: int
        :param MODE: 1 for encryption, 0 for decryption
        :return: file_name.SM4_CTR
        """
        if MODE == 0 and file_path[-8:] != '.SM4_CTR':
            raise ValueError('File format error')


        f = open(file_path, 'rb')
        file_name = file_path + '.SM4_CTR'
        message = []
        while True:
            tmp = f.read(1)
            if not tmp:
                break
            message.append(int.from_bytes(tmp, byteorder='big'))

        f.close()
        if MODE == 1:
            f = open(file_name, 'wb')
        else:
            f = open(file_path[:-8], 'wb')
        l = len(message)
        length_ = math.ceil(l / 16)
        CTRkey = self.CTR_get_key(IV, length_)
        for i in range(length_ - 1):
            ou = b''
            x = 0
            for j in range(16):
                x += message[i * 16 + j] << (8 * (15 - j))
            res = CTRkey[i] ^ x
            for j in range(16):
                ou += bytes([res >> (8 * (15 - j)) & 255])
            f.write(ou)
        rem = l % 16
        x = 0
        ou = b''
        for i in range(rem):
            x += message[(length_ - 1) * 16 + i] << (8 * (15 - i))
        res = CTRkey[length_ - 1] ^ x
        for i in range(rem):
            ou += bytes([res >> (8 * (15 - i)) & 255])
        f.write(ou)
        f.close()

    def CFB_get_key(self, IV, n):
        res = self.SM4_encrypt(IV)
        res = res >> (128 - n * 8)

        return res

    def SM4_CFB(self, file_path, IV, n, MODE):
        """
        :param file_path: path of file
        :param IV: hex(length 32) no '0x'
        :param n: bytes number
        :param MODE: 1 for encode 0 for decode
        :return: file_name.SM4_OFB
        """
        IV = int(IV, 16)
        if MODE == 0 and file_path[-8:] != '.SM4_CFB':
            raise ValueError('File format error')

        f = open(file_path, 'rb')
        file_name = file_path + '.SM4_CFB'
        message = []
        while True:
            tmp = f.read(1)
            if not tmp:
                break
            message.append(int.from_bytes(tmp, byteorder='big'))
        f.close()

        """
        then, we should do the encryption and decryption
        """

        if MODE == 1:
            f = open(file_name, 'wb')
            l = len(message)
            length_ = math.ceil(l / n)

            for i in range(length_ - 1):
                ou = b''
                x = 0
                for j in range(n):
                    x += message[i * n + j] << (8 * (n - 1 - j))
                CFBkey = self.CFB_get_key(IV, n) >> (128 - n * 8)
                IV = (IV << (n * 8)) + x
                res = CFBkey ^ x
                for j in range(n):
                    ou += bytes([res >> (8 * (n - 1 - j)) & 255])
                f.write(ou)
            rem = len(message) % n
            x = 0
            for j in range(rem):
                x += message[(length_ - 1) * n + j] << (8 * (rem - 1 - j))
            CFBkey = self.CFB_get_key(IV, n) >> (128 - n * 8)
            IV = (IV << (n * 8)) + x
            res = CFBkey ^ x
            ou = b''
            for j in range(rem):
                ou += bytes([res >> (8 * (rem - 1 - j)) & 255])
            f.write(ou)
            f.close()
        else:
            f = open(file_path[:-8], 'wb')
            l = len(message)
            length_ = math.ceil(l / n)
            for i in range(length_ - 1):
                ou = b''
                x = 0
                for j in range(n):
                    x += message[i * n + j] << (8 * (n - 1 - j))
                CFBkey = self.CFB_get_key(IV, n) >> (128 - n * 8)
                IV = (IV << (n * 8)) + x
                res = CFBkey ^ x
                for j in range(n):
                    ou += bytes([res >> (8 * (n - 1 - j)) & 255])
                f.write(ou)
            rem = len(message) % n
            x = 0
            for j in range(rem):
                x += message[(length_ - 1) * n + j] << (8 * (rem - 1 - j))
            CFBkey = self.CFB_get_key(IV, n) >> (128 - n * 8)
            IV = (IV << (n * 8)) + x
            res = CFBkey ^ x
            ou = b''
            for j in range(rem):
                ou += bytes((res >> (8 * (rem - 1 - j))) & 255)
            f.write(ou)
            f.close()














