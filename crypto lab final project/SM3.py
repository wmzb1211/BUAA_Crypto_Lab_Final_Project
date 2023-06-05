class SM3:
    IV = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e
    T1 = 0x79cc4519
    T2 = 0x7a879d8a
    MOD = 0xffffffff

    def help(self):
        print('you can use help() to get help')
        print('if you wanna use hash, you can use hash_sm3()')
        print('    the parameters of hash() you should input are:msg')
        print('    msg: the message you wanna hash (a string or bytes)')
        print('Thank you for using SM3!')
    def padding(self, msg):
        # print(msg.__len__() * 8 // 512)
        msg_len = msg.__len__()
        # print(msg_len)
        hl = [int((hex(msg_len * 8)[2:]).rjust(16, '0')[i:i + 2], 16)
              for i in range(0, 16, 2)]
        l0 = (56 - msg_len) % 64
        if l0 == 0:
            l0 = 64
        if isinstance(msg, str):
            msg += chr(0b10000000)
            msg += chr(0) * (l0 - 1)
            for a in hl:
                msg += chr(a)
        elif isinstance(msg, bytes):
            msg += bytes([0b10000000])
            msg += bytes(l0 - 1)
            msg += bytes(hl)
        return msg

    def FF(self, X, Y, Z, i):
        if i <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)

    def GG(self, X, Y, Z, i):
        if i <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | ((~X) & Z)

    def leftShift(self, x, n):
        return ((x << n) & ((1 << 32) - 1)) | (x >> (32 - n))

    def P0(self, X):
        return X ^ self.leftShift(X, 9) ^ self.leftShift(X, 17)

    def P1(self, X):
        return X ^ self.leftShift(X, 15) ^ self.leftShift(X, 23)

    def grouping(self, msg):
        n = msg.__len__() // 64
        B = [msg[i:i + 64] for i in range(0, msg.__len__(), 64)]
        return B

    def CF(self, Vi, W, W_, T):
        A = (Vi >> 224) & ((1 << 32) - 1)
        B = (Vi >> 192) & ((1 << 32) - 1)
        C = (Vi >> 160) & ((1 << 32) - 1)
        D = (Vi >> 128) & ((1 << 32) - 1)
        E = (Vi >> 96) & ((1 << 32) - 1)
        F = (Vi >> 64) & ((1 << 32) - 1)
        G = (Vi >> 32) & ((1 << 32) - 1)
        H = Vi & ((1 << 32) - 1)
        for j in range(64):
            ss1 = self.leftShift(((self.leftShift(A, 12) + E + self.leftShift(T[j], j % 32)) & ((1 << 32) - 1)), 7)
            ss2 = ss1 ^ self.leftShift(A, 12)
            tt1 = (self.FF(A, B, C, j) + D + ss2 + W_[j]) & ((1 << 32) - 1)
            tt2 = (self.GG(E, F, G, j) + H + ss1 + W[j]) & ((1 << 32) - 1)
            D = C
            C = self.leftShift(B, 9)
            B = A
            A = tt1
            H = G
            G = self.leftShift(F, 19)
            F = E
            E = self.P0(tt2)
        temp = ((A << 224) | (B << 192) | (C << 160) | (D << 128) | (E << 96) | (F << 64) | (G << 32) | H) ^ Vi
        return temp

    def Msgdiffusion(self, Bi):
        W = []
        W_ = []
        for i in range(16):
            temp = Bi[i * 4:i * 4 + 4]
            temp = (temp[0] << 24) + (temp[1] << 16) + (temp[2] << 8) + temp[3]
            W.append(temp)
        for i in range(16, 68):
            W.append(self.P1(W[i - 16] ^ W[i - 9] ^ self.leftShift(W[i - 3], 15)) ^ self.leftShift(W[i - 13], 7) ^ W[i - 6])
        for i in range(0, 64):
            W_.append(W[i] ^ W[i + 4])
        return W, W_

    def IterativeCompression(self, msg, Mlen, T):
        n = Mlen // 512
        B = self.grouping(msg)
        V = [0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e]

        for i in range(n):
            W, W_ = self.Msgdiffusion(B[i])
            V.append(self.CF(V[i], W, W_, T))
        return V[n]

    def hash_sm3(self, msg):
        """
        :param msg: the message you wanna hash (a string or bytes)
        :return: the hash value of the message (a string)
        """
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        msg = self.padding(msg)
        iv = self.IV
        T = []
        for i in range(64):
            if i <= 15:
                T.append(0x79cc4519)
            else:
                T.append(0x7a879d8a)
        Mlen = len(msg) * 8
        temp = hex(self.IterativeCompression(msg, Mlen, T))[2:]
        for i in range(64 - len(temp)):
            temp = '0' + temp
        return temp







