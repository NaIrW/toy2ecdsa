from Crypto.Util.number import *
from hashlib import sha256


class Paillier:
    def __init__(self, pub=None, nbits=2048):
        if not pub:
            pbits = nbits // 2
            _p, _q = getPrime(pbits), getPrime(pbits)
            self.n = _p * _q
            self.lam = (_p - 1) * (_q - 1)
            self.g = self.n + 1
            self.mu = inverse(self.lam, self.n)
        else:
            self.n = pub
            self.g = pub + 1

    def encrypt(self, m):
        r = getRandomRange(2, self.n)
        c = pow(self.g, m, self.n ** 2) * pow(r, self.n, self.n ** 2) % self.n ** 2
        return c
    
    def decrypt(self, c):
        m = ((pow(c, self.lam, self.n ** 2) - 1) // self.n) * self.mu % self.n
        return m
    
    def getPub(self):
        return self.n


class EllipticCurvePoint:
    def __init__(self, point, ainvs, p, n=None):
        if point[0] is not None:
            self.x = point[0] % p
        else:
            self.x = None
        if point[1] is not None:
            self.y = point[1] % p
        else:
            self.y = None
        self.ainvs = ainvs
        if len(ainvs) == 2:
            self.a1 = 0
            self.a2 = 0
            self.a3 = 0
            self.a4 = ainvs[0]
            self.a6 = ainvs[1]
        elif len(ainvs) == 5:
            self.a1 = ainvs[0]
            self.a2 = ainvs[1]
            self.a3 = ainvs[2]
            self.a4 = ainvs[3]
            self.a6 = ainvs[4]
        self.p = p
        self.n = n
        assert self.is_on_curve()

    def is_on_curve(self):
        if self.x is None and self.y is None:

            return True
        x, y = self.x, self.y
        return (y * y + self.a1 * x * y + self.a3 * y - x * x * x - self.a2 * x * x - self.a4 * x - self.a6) % self.p == 0

    def __neg__(self):
        assert self.is_on_curve()
        if self.x is None and self.y is None:
            return EllipticCurvePoint((None, None), self.ainvs, self.p)
        x, y = self.x, self.y
        return EllipticCurvePoint((x, (-y - self.a1 * x - self.a3) % self.p), self.ainvs, self.p)

    def __sub__(self, other):
        return self.__add__(-other)

    def __add__(self, other):
        assert self.ainvs == other.ainvs and self.p == other.p
        if self.x is None and self.y is None:
            return other
        if other.x is None and other.y is None:
            return self
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        if x1 == x2 and y1 == (-y2 - self.a1 * x2 - self.a3) % self.p:
            return EllipticCurvePoint((None, None), self.ainvs, self.p)
        if x1 == x2 and y1 == y2:
            m = (3 * x1 * x1 + 2 * self.a2 * x1 + self.a4 - self.a1 * y1) * inverse(2 * y1 + self.a1 * x1 + self.a3, self.p)
        else:
            m = (y1 - y2) * inverse(x1 - x2, self.p)
        x3 = -x1 - x2 - self.a2 + m * (m + self.a1)
        y3 = -y1 - self.a3 - self.a1 * x3 + m * (x1 - x3)
        return EllipticCurvePoint((x3, y3), self.ainvs, self.p)

    def __mul__(self, k):
        if k < 0:
            return -k * -self
        result = EllipticCurvePoint((None, None), self.ainvs, self.p)
        addend = self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __rmul__(self, other):
        return self * other

    def __str__(self):
        return f'({self.x}, {self.y})'

    def hex(self):
        return '{:064x}{:064x}'.format(self.x, self.y).encode()


class EllipticCurve:
    def __init__(self, ainvs, p):
        assert isPrime(p)
        self.ainvs = [each % p for each in ainvs]
        self.p = p

    def __call__(self, point, n=None):
        return EllipticCurvePoint(point, self.ainvs, self.p, n)

    def fromHex(self, point):
        return self.__call__((int(point[:64], 16), int(point[64:], 16)))


# secp256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
q = n
E = EllipticCurve([a, b], p)
G = E(G, n)


def randPoint():
    x = getRandomRange(2, n)
    return x, x * G


def Hash(msg):
    return sha256(msg).hexdigest().encode()


def nizkPoK(point, sk):
    r = getRandomRange(2, q)
    R = r * G
    c = int(Hash(point.hex() + R.hex()), 16)
    z = r + c * sk
    return R.hex() + hex(z % q)[2:].encode()


def verifzk(nizk, point):
    R, z = E.fromHex(nizk[:128]), int(nizk[128:], 16)
    c = int(Hash(point.hex() + R.hex()), 16)
    return (z * G).hex() == (R + c * point).hex()


# if __name__ == '__main__':
#     q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
#
#     # part 1
#     a = getRandomRange(2, q)
#     # part 2
#     b = getRandomRange(2, q)
#
#     # setup
#     part2 = Paillier()
#     pk = part2.getPub()
#
#     # send pk to part 1
#     part1 = Paillier(pk)
#
#     # multiplication
#     cb = part2.encrypt(b)
#
#     # send cb to part 1
#
#     _alpha = getRandomRange(2, q)
#
#     ca = pow(cb, a, pk ** 2) * part1.encrypt(_alpha) % pk ** 2
#
#     # send ca to part 2
#
#     beta = part2.decrypt(ca) % q
#
#     alpha = -_alpha % q
#
#     print(a * b % q)
#     print((alpha + beta) % q)
