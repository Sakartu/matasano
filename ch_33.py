#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_33.py
"""
import textwrap
import sys
import time
import util

__author__ = 'peter'


def main():
    t0 = time.time
    print('Testing Diffie-Hellman session key generation with simple params')

    if not test_pair(37, 5):
        print('Test failed!')
        sys.exit(-1)

    print('Test succeeded, testing with real world params')

    p = int(textwrap.dedent('''
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff''').replace('\n', ''), 16)
    g = 2

    if not test_pair(p, g):
        print('Test failed!')
        sys.exit(-1)

    print('Test succeeded, total test time was {}ms'.format(time.time() - t0))


def test_pair(p, g):
    priv1, pub1 = util.dh_gen_keypair(p, g)
    priv2, pub2 = util.dh_gen_keypair(p, g)
    return util.dh_gen_session_key(p, priv1, pub2) == util.dh_gen_session_key(p, priv2, pub1)


if __name__ == '__main__':
    main()
