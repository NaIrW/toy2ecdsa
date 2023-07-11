# part 2

import socketserver
from util import *


class Server(socketserver.BaseRequestHandler):

    def handle(self):
        self.buffer = b''

        """
        Distributed Key Generation Phase
        """

        f1 = self._recv()

        # P2's first message
        x2, Q2 = randPoint()
        nizk2 = nizkPoK(Q2, x2)
        self._send(Q2.hex())
        self._send(nizk2)

        # P2’s verification
        Q1 = E.fromHex(self._recv())
        nizk1 = self._recv()
        assert verifzk(nizk1, Q1)
        assert f1 == Hash(Q1.hex() + nizk1)

        # Compute output
        # Q = Q1 + Q2

        """
        Distributed Sign Phase
        """

        # Commitment of P2’s nonce

        k2, R2 = randPoint()
        nizk3 = nizkPoK(R2, k2)
        f2 = Hash(R2.hex() + nizk3)
        self._send(f2)

        # MtA and Consistency Check

        tb = self.MtA(k2)

        _Q1r1cc = self._recv()
        _Q1, r1, cc = E.fromHex(_Q1r1cc[:128]), int(_Q1r1cc[128:64+128], 16), int(_Q1r1cc[-64:], 16)
        assert ((tb + cc) * G).hex() == ((r1 + k2) * _Q1 - Q1).hex()

        _x2 = (x2 - (tb + cc)) % q

        """
        Nonce Key Exchange
        """

        R1 = E.fromHex(self._recv())
        nizk4 = self._recv()
        assert verifzk(nizk4, R1)

        self._send(R2.hex())
        self._send(nizk3)
        R = (k2 + r1) * R1
        r = R.x

        """
        Online Signature
        """
        msg2sign = b'https://github.com/NaIrW/toy2ecdsa'
        h = int(Hash(msg2sign), 16)
        s2 = inverse(k2 + r1, q) * (h + r * _x2) % q
        self._send(str(s2))

    def MtA(self, value):
        """
        Paillier based
        :param value:
        :return:
        """
        cipher = Paillier()
        pk = cipher.getPub()
        self._send(str(pk).encode())

        cb = cipher.encrypt(value)
        self._send(str(cb).encode())

        ca = int(self._recv().decode())
        beta = cipher.decrypt(ca) % q

        return beta

    def _recv(self):
        if b'\n' in self.buffer:
            res, self.buffer = self.buffer.split(b'\n', 1)
        else:
            self.buffer += self.request.recv(512)
            return self._recv()
        return res

    def _send(self, msg):
        if isinstance(msg, bytes):
            msg += b'\n'
        else:
            msg += '\n'
            msg = msg.encode()
        self.request.sendall(msg)


class ForkedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 10001
    server = ForkedServer((HOST, PORT), Server)
    server.allow_reuse_address = True
    server.serve_forever()
