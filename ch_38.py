#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_37.py
"""
import hashlib
import random
import textwrap
import util
import hmac

__author__ = 'peter'


def main():
    n = int(textwrap.dedent('''
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff''').replace('\n', ''), 16)

    print('Testing regular simplified SRP')
    log_in('password', n, False)
    print('\nTesting MITM')
    # Pick a random password from the dict
    log_in(random.choice([x.strip() for x in open('resources/wordlist.txt')]), n, True)
    print('All tests passed')


# noinspection PyPep8Naming
def log_in(password, n, mitm):
    print('Generating key(s) for SRP')
    # Set p and g to the NIST specified parameters
    g = 2

    if mitm:
        bot = util.MITMSSRPBot(g, n, password)
    else:
        bot = util.SSRPBot(g, n, password)

    a, A = util.dh_gen_keypair(n, g)

    salt, B, u = bot.init_session(A)

    x = int('0x' + hashlib.sha256((salt + password).encode('utf8')).hexdigest(), 16)
    S = pow(B, a + u*x, n)
    K = hashlib.sha256(str(S).encode('utf8'))

    print('C: Checking key')
    hmc = hmac.new(K.digest(), salt.encode('utf8'), hashlib.sha256).digest()
    if bot.check_key(hmc):
        print('C: Keys are correct!')
    else:
        raise Exception('C: Keys do not correlate!')


if __name__ == '__main__':
    main()
