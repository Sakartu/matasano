#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
cbc_bitflipping.py
"""
from itertools import product

from docopt import docopt
import sys
import util

__author__ = 'peter'


def main():
    cipher = lambda plain: cbc_enc_ch_16(plain)
    decipher = lambda ct: cbc_dec_ch_16(ct)

    # Two plaintext blocks of 16 bytes
    pt = 'aaaaaaaaaaaaaaaa' + '0admin1true2aaaa'
    # block to encrypt will be prefix + pt + postfix:
    # "comment1=cooking" + "%20MCs;userdata=" + "aaaaaaaaaaaaaaaa" + "0admin1true2aaaa" + ";comment2=%20lik" +
    # "e%20a%20pound%20" + "of%20bacon"
    # We will flip bits in the "aaaaaaaaaaaaaaaa" part, to change bits in the "0admin1true2aaaa" part
    print('Bruting...')
    ct = cipher(pt)
    for idx, (a, b, c) in enumerate(product(range(255), range(255), range(255))):
        tampered = bytearray(ct)
        tampered[32] = a  # 0 + 32, loc of first ;
        tampered[38] = b  # 6 + 32, loc of =
        tampered[43] = c  # 11 + 32, loc of second ;
        tampered = bytes(tampered)
        if not idx % 100000:
            sys.stderr.write('.')

        if decipher(tampered):
            print()
            print(ct)


def cbc_enc_ch_16(plain, prepend=None, append=None):
    if prepend is None:
        prepend = "comment1=cooking%20MCs;userdata="
    if append is None:
        append = ";comment2=%20like%20a%20pound%20of%20bacon"
    plain = plain.translate(str.maketrans('', '', ';='))
    plain = prepend + plain + append
    return util.aes_cbc_encrypt(bytes(plain, 'utf8'), util.GLOBAL_KEY)


def cbc_dec_ch_16(ct, check=b';admin=true;'):
    pt = util.aes_cbc_decrypt(ct, util.GLOBAL_KEY)
    return check in pt


if __name__ == '__main__':
    main()