#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_16.py
"""
from itertools import product

from docopt import docopt
import sys
import util

__author__ = 'peter'


def main():
    # Two plaintext blocks of 16 bytes
    pt = b'aaaaaaaaaaaaaaaa' + b'0admin1true2aaaa'
    # block to encrypt will be prefix + pt + postfix:
    # "comment1=cooking" + "%20MCs;userdata=" + "aaaaaaaaaaaaaaaa" + "0admin1true2aaaa" + ";comment2=%20lik" +
    # "e%20a%20pound%20" + "of%20bacon"
    # We will flip bits in the "aaaaaaaaaaaaaaaa" part, to change bits in the "0admin1true2aaaa" part
    print('Bruting...')
    ct = cbc_enc_ch_16(pt)
    for idx, (a, b, c) in enumerate(product(range(255), range(255), range(255))):
        tampered = bytearray(ct)
        tampered[32] = a  # 0 + 32, loc of first ;
        tampered[38] = b  # 6 + 32, loc of =
        tampered[43] = c  # 11 + 32, loc of second ;
        tampered = bytes(tampered)
        if not idx % 100000:
            sys.stderr.write('.')

        if cbc_dec_ch_16(tampered):
            print('Found ciphertext with ";admin=true;" in it:')
            print(ct)
            return


def cbc_enc_ch_16(plain):
    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"
    plain = plain.replace(b';', b'')
    plain = plain.replace(b'=', b'')
    plain = prepend + plain + append
    return util.aes_cbc_encrypt(plain, util.GLOBAL_KEY)


def cbc_dec_ch_16(ct, check=b';admin=true;'):
    pt = util.aes_cbc_decrypt(ct, util.GLOBAL_KEY)
    return check in pt


if __name__ == '__main__':
    main()