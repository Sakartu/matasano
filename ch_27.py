#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_27.py
"""
from itertools import product

from docopt import docopt
import sys
import exceptions
import util

__author__ = 'peter'


def main():
    key = util.get_random_bytes(16)
    pt = util.get_random_bytes(16 * 3)  # 3 blocks of 16 bytes
    print('Encrypting plaintext at sender side')
    ct = cipher(pt, key)  # This is the sender, he knows the key
    print('Tampering ciphertext at attacker side')
    tampered_ct = ct[:16] + b'\x00' * 16 + ct[:16]  # This is the attacker, who doesn't know the key but can mitm
    assert len(ct) == len(tampered_ct)
    try:
        # There is a very high chance this will throw an error
        print('Decrypting tampered ciphertext')
        decipher(tampered_ct, key)  # This is the receiver, he knows the key also
    except exceptions.InvalidPlaintextError as e:
        print('Decryption threw an error, we can now get the key')
        # The attacker receives the error, which contains the broken plaintext, from which we can get the key:
        assert key == util.fixed_xor(e.invalid_plaintext[:16], e.invalid_plaintext[32:48])
        print('Key successfully extracted!')
        # The reason this works is because:
        # CT1' = AES(PT1 ^ K)
        # CT2' = 0
        # CT3' = AES(PT1 ^ K)
        #
        # PT1' = AES-1(AES(PT1 ^ K)) ^ K = PT1 ^ K ^ K = PT1
        # PT2' = AES-1(AES(0)) ^ AES(PT1 ^ K) = AES(PT1 ^ K)
        # PT3' = AES-1(AES(PT1 ^ K)) ^ 0 = PT1 ^ K
        # PT1' ^ PT3' = PT1 ^ PT1 ^ K = K


def cipher(plain, key):
    return util.aes_cbc_encrypt(plain, key, key, pad=False)


def decipher(ct, key):
    pt = util.aes_cbc_decrypt(ct, key, key, depad=False)
    if not util.is_ascii(pt):
        raise exceptions.InvalidPlaintextError(pt)


if __name__ == '__main__':
    main()