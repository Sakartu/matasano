#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_25
"""
import base64
import util

__author__ = 'peter'


def test_edit():
    pt = b'AAAABBBBCCCCDDDD'
    key = util.get_random_bytes(16)
    ct1 = util.aes_ctr_encrypt(pt, key)
    ct2 = util.aes_ctr_edit(ct1, key, 12, b'EEEE')
    assert util.aes_ctr_decrypt(ct2, key) == pt[:12] + b'EEEE'


def main():
    # Make sure the edit function works properly
    test_edit()

    print('Reading resource')
    pt1 = base64.b64decode(''.join(open('resources/ch_25.txt')))
    key = util.get_random_bytes(16)

    print('Encrypting')
    ct1 = util.aes_ctr_encrypt(pt1, key)

    print('Using oracle to encrypt chosen plaintext')
    pt2 = b'A' * len(ct1)
    ct2 = util.aes_ctr_edit(ct1, key, 0, pt2)

    print('Recreating keystream using chosen plaintext and it\'s encrypted version, by editing from offset 0')
    # We can now recreate the keystream:
    # ct1 = ks ^ pt1
    # ct2 = ks ^ pt2
    # ks = pt2 ^ ct2 = pt2 ^ ks ^ pt2
    ks = util.fixed_xor(pt2, ct2)
    # pt1 = ct1 ^ ks
    if pt1 == util.fixed_xor(ct1, ks):
        print('We have successfully broken the reused key CTR encryption!')
    else:
        print('We couldn\'t crack the reused key CTR encryption!')


if __name__ == '__main__':
    main()
