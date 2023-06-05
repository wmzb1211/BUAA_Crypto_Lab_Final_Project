from SM3 import SM3
from Math_crypto import invmod, Egcd

class SM2:
    # y^2 = x^3 + ax + b (mod p)
    def __init__(self, a, b ,p, G, n):
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n
        # if self.test() == False:
        #     raise ValueError('G is not a point on the curve')

    def help(self):
        print('five init parameters: a, b, p, G, n')
        print('a, b, p are parameters of the elliptic curve')
        print('G is the base point of the elliptic curve')
        print('n is the order of the base point')
        print('you can use help() to get help')
        print('if you wanna use signature, you can use sign()')
        print('    the parameters of sign() you should input are:ID_A, P_A, M, d_A, k')
        print('    ID_A: the ID of the signer (a string)')
        print('    P_A: the public key of the signer (a point on the elliptic curve)')
        print('    M: the message you wanna sign (a string)')
        print('    d_A: the private key of the signer (a number)')
        print('    k: a random number (a number)')
        print('if you wanna use verification, you can use verify()')
        print('    the parameters of verify() you should input are:ID_A, P_A, M, r, s')
        print('    ID_A: the ID of the signer (a string)')
        print('    P_A: the public key of the signer (a point on the elliptic curve)')
        print('    M: the message you wanna sign (a string)')
        print('    r: the first part of the signature (a number)')
        print('    s: the second part of the signature (a number)')
        print('Thank you for using SM2!')


    def test(self):
        isorder = self.multi(self.G[0], self.G[1], self.n)
        if isorder == [0, 0]:
            return True
        else:
            return False

    def add(self, P, Q):
        """
        :param P: Coordinates of points on the elliptic curve
        :param Q: Coordinates of points on the elliptic curve
        :return: Coordinates of points on the elliptic curve that is the sum of P and Q
        """
        x1 = P[0]
        y1 = P[1]
        x2 = Q[0]
        y2 = Q[1]
        if x1 == x2 and y1 == y2:
            x3 = ((((3 * x1 * x1 + self.a) ** 2) % self.p) * (((invmod(2 * y1, self.p)) ** 2) % self.p) - 2 * x1) % self.p
            y3 = (((3 * (x1 ** 2) + self.a) % self.p) * (x1 - x3) * invmod(2* y1, self.p) - y1) % self.p
        else:
            delta_x = (x1 - x2) % self.p
            delta_y = (y1 - y2) % self.p
            n_m = (delta_y * invmod(delta_x, self.p)) % self.p
            n_m_2 = (n_m * n_m) % self.p
            x3 = (n_m_2 - x1 - x2) % self.p
            y3 = (- y2 + n_m * (x2 - x3)) % self.p
        return x3, y3

    def sub(self, P, Q):
        """
        :param P: Coordinates of points on the elliptic curve
        :param Q: Coordinates of points on the elliptic curve
        :return: Coordinates of points on the elliptic curve that is the difference of P and Q
        """
        x1 = P[0]
        y1 = P[1]
        x2 = Q[0]
        y2 = Q[1]
        if x1 == x2 and y1 == y2:
            return 0, 0
        else:
            x4, y4 = self.add((x1, y1), (x2, -y2 % self.p))
            return x4, y4

    def multi(self, x, y, k):
        """
        :param x: abscissa of the point, is a Biginteger
        :param y: ordinate of the point, is a Biginteger
        :param k: multiplier k, is an integer
        :return: Coordinates of points on the elliptic curve that is the product of k and (x, y)
        """
        while k & 1 == 0:
            x, y = self.add((x, y), (x, y))
            k = k // 2
        x3, y3 = x, y
        x, y = self.add((x, y), (x, y))
        k = k // 2
        # x3, y3 = 0, 0
        while k > 0:
            if k & 1 == 1:
                x3, y3 = self.add((x3, y3), (x, y))
            x, y = self.add((x, y), (x, y))
            k = k // 2
        return x3, y3

    def step_1_padding(self, msg):
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

    def grouping(self, msg):
        n = msg.__len__() // 64
        B = [msg[i:i + 64] for i in range(0, msg.__len__(), 64)]
        return B

    def leftShift(self, x, n):
        return ((x << n) & ((1 << 32) - 1)) | (x >> (32 - n))

    def get_Z_A(self, ID_A, P_A):
        ENTL_A = hex(len(ID_A.encode() * 8))[2:].zfill(4)
        ID_A = ID_A.encode().hex()
        temp = ENTL_A + ID_A
        G0 = int(self.G[0])
        G1 = int(self.G[1])
        P_A0 = int(P_A[0])
        P_A1 = int(P_A[1])

        for int_number in self.a, self.b, G0, G1, P_A0, P_A1:
            temp += hex(int_number)[2:].zfill(64)
        # print('temp', temp)
        ss = SM3()
        Z_A = ss.hash_sm3(bytes.fromhex(temp))
        return Z_A
    def sign(self, ID_A, P_A, M, d_A, k):
        """
        :param ID_A: String ID_A, representing the identity of A
        :param P_A: Coordinates of points on the elliptic curve that is the public key of A
        :param M: String M, representing the message to be signed
        :param d_A: Private key of A is an integer
        :param k: Random number k
        :return: Signature of A
        """
        Z_A = self.get_Z_A(ID_A, P_A)
        temp = Z_A + M.encode('utf-8').hex()
        ss = SM3()
        e = ss.hash_sm3(bytes.fromhex(temp))
        e = int(e, 16)
        x1, y1 = self.multi(self.G[0], self.G[1], k)
        r = (e + x1) % self.n
        s = (invmod(1 + d_A, self.n) * (k - r * d_A)) % self.n
        return r, s

    def verify(self, ID_A, P_A, M, r, s):
        """
        :param ID_A: String ID_A, representing the identity of A
        :param P_A: Coordinates of points on the elliptic curve that is the public key of A
        :param M: String M, representing the message to be signed
        :param r: A positive integer r representing r in the signature
        :param s: A positive integer s representing s in the signature
        :return: True if the signature is valid, False otherwise
        """
        Z_A = self.get_Z_A(ID_A, P_A)
        temp = Z_A + M.encode('utf-8').hex()
        ss = SM3()
        e = ss.hash_sm3(bytes.fromhex(temp))
        e = int(e, 16)
        t = (r + s) % self.n
        x1, y1 = self.multi(self.G[0], self.G[1], s)
        x2, y2 = self.multi(P_A[0], P_A[1], t)
        x, y = self.add((x1, y1), (x2, y2))
        R = (e + x) % self.n
        if R == r:
            return True
        else:
            return False