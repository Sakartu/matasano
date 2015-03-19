#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
test_cbc.py

Options:
"""
import random
import binascii

import util

__author__ = 'peter'


def main():
    for _ in range(10000):
        pt = util.get_random_bytes(random.randint(2, 16))
        key = util.get_random_bytes(16)
        iv = util.get_random_bytes(16)
        ct = util.aes_cbc_encrypt(pt, key, iv)
        dpt = util.aes_cbc_decrypt(ct, key, iv)
        try:
            assert pt == dpt
        except AssertionError:
            print(binascii.hexlify(pt))
            print(binascii.hexlify(dpt))
            raise


if __name__ == '__main__':
    main()