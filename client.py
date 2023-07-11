# part 1

from pwn import *
from util import *


ip, port = '127.0.0.1', 10001
io = remote(ip, port)


def MtA(value):
    pk = int(io.recvline(False).decode())
    cipher = Paillier(pk)

    cb = int(io.recvline(False).decode())

    _alpha = getRandomRange(2, q)
    ca = pow(cb, value, pk ** 2) * cipher.encrypt(_alpha) % pk ** 2

    io.sendline(str(ca).encode())

    alpha = -_alpha % q

    return alpha


if __name__ == '__main__':
    """
    Distributed Key Generation Phase
    """

    # P1's first message
    x1, Q1 = randPoint()
    nizk1 = nizkPoK(Q1, x1)
    f1 = Hash(Q1.hex() + nizk1)
    io.sendline(f1)

    Q2 = E.fromHex(io.recvline(False))
    nizk2 = io.recvline(False)

    # P1’s second message
    assert verifzk(nizk2, Q2)
    io.sendline(Q1.hex())
    io.sendline(nizk1)

    # Compute output
    Q = Q1 + Q2

    """
    Distributed Sign Phase
    """

    f2 = io.recvline(False)

    # MtA and Consistency Check

    _x1, _Q1 = randPoint()

    ta = MtA(_x1)

    r1 = getRandomRange(2, q)
    cc = (ta + _x1 * r1 - x1) % q

    io.sendline(_Q1.hex() + '{:064x}{:064x}'.format(r1, cc).encode())

    """
    Nonce Key Exchange
    """

    k1, R1 = randPoint()
    nizk4 = nizkPoK(R1, k1)
    io.sendline(R1.hex())
    io.sendline(nizk4)

    R2 = E.fromHex(io.recvline(False))
    nizk3 = io.recvline(False)
    assert verifzk(nizk3, R2)

    R = k1 * R2 + k1 * r1 * G
    r = R.x

    """
    Online Signature
    """

    s2 = int(io.recvline(False))

    s = inverse(k1, q) * (s2 + r * _x1) % q

    msg2sign = b'https://github.com/NaIrW/toy2ecdsa'
    h = int(Hash(msg2sign), 16)

    assert r == (h * inverse(s, q) * G + r * inverse(s, q) * Q).x

    print('{:064x}{:064x}'.format(r, s).encode())
