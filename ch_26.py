#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_26.py
"""

import util

__author__ = 'peter'


def main():
    # Two plaintext blocks of 16 bytes each
    key = util.get_random_bytes(16)
    pt1 = b'aaaaaaaaaaaaaaaa'
    pt2 = b'bbbbbbbbbbbbbbbb'
    ct1 = cipher(pt1, key)
    ct2 = cipher(pt2, key)

    # Find the first changed byte
    idx = [a != b for a, b in zip(ct1, ct2)].index(True)
    want = b';admin=true;aaaa'
    print('First different byte is at index {}'.format(idx))
    ks = util.fixed_xor(pt2, ct2[idx:idx + len(want)])
    assert len(ks) == len(want)

    print("Calculating relevant keystream")
    want_ct = util.fixed_xor(ks, want)
    tampered_ct = ct1[:idx] + want_ct + ct1[idx + len(want_ct):]
    if decipher(tampered_ct, key):
        print("Tampered ciphertext constructed, which decrypts to a plaintext containing ;admin=true;!")


def cipher(plain, key):
    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"
    plain = plain.replace(b';', b'')
    plain = plain.replace(b'=', b'')
    plain = prepend + plain + append
    return util.aes_ctr_encrypt(plain, key)


def decipher(ct, key, check=b';admin=true;'):
    pt = util.aes_ctr_decrypt(ct, key)
    return check in pt


if __name__ == '__main__':
    main()
