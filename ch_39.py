#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_37.py
"""
import hashlib
import random
import string
import textwrap
import util
import hmac

__author__ = 'peter'


def main():
    params = [
        (240, 46),
        (120, 23),
        (421, 111),
        (93, 219),
        (4864, 3458)
    ]
    print('Testing egcd implementation')
    for p in params:
        test_egcd(*p)
    print('Test successful')

    params = [
        (240, 46, False),
        (120, 23, True),
        (421, 111, True),
        (93, 219, False),
        (4864, 3458, False),
        (50, 71, True),
        (43, 64, True),
        (26, 7, True),
        (216, 37, True),
        (3120, 17, True)
    ]
    print('Testing invmod')
    for p in params:
        test_invmod(*p)
    print('Test successful')

    n = 128
    print('Testing RSA implementation with {}-bit primes'.format(n))
    test_rsa(n)
    print('Test successful')

    n = 2048
    print('Testing RSA implementation with {}-bit primes (this could take a while)'.format(n))
    test_rsa(n)
    print('Test successful')


def test_egcd(a, b):
    gcd, x, y = util.egcd(a, b)
    assert x*a + y*b == gcd
    print('{}*{} + {}*{} == {}'.format(x, a, y, b, gcd))


def test_invmod(a, b, success=True):
    inv = util.invmod(a, b)
    if success:
        assert inv * a % b == 1
        print('{} * {} % {} == 1'.format(inv, a, b))
    else:
        assert inv is None
        print('No x exists such that x * {} % {} == 1'.format(a, b))


def test_rsa(n):
    rsa = util.RSA(n)

    m = 'Test message'
    msg = util.str_to_int(m)
    ct = rsa.encrypt(msg)
    assert m == util.int_to_str(rsa.decrypt(ct))


if __name__ == '__main__':
    main()
