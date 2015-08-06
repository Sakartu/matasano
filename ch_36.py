#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_36.py
"""
import hashlib
import textwrap
import util
import hmac

__author__ = 'peter'


# noinspection PyPep8Naming
def main():
    print('Generating key(s) for SRP')
    # Set p and g to the NIST specified parameters
    N = int(textwrap.dedent('''
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff''').replace('\n', ''), 16)
    g = 2
    k = 3
    P = util.generate_random_string()

    bot = util.SRPBot(N, g, k, P)

    a, A = util.dh_gen_keypair(N, g)
    salt, B = bot.init_session(A)
    u = int('0x' + hashlib.sha256((str(A) + str(B)).encode('utf8')).hexdigest(), 16)
    assert u == bot.u

    x = int('0x' + hashlib.sha256((salt + P).encode('utf8')).hexdigest(), 16)
    assert x == bot.x

    S = pow(B - k * pow(g, x, N), a + u * x, N)
    assert S == bot.S

    K = hashlib.sha256(str(S).encode('utf8'))
    assert bot.K.hexdigest() == K.hexdigest()

    print('Checking key')
    hmc = hmac.new(K.digest(), salt.encode('utf8'), hashlib.sha256).digest()
    if bot.check_key(hmc):
        print('Keys are correct!')
    else:
        raise Exception('Keys do not correlate!')


if __name__ == '__main__':
    main()
