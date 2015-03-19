#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
byte_by_byte_ecb.py

Options:
"""
import base64
import pprint
from Crypto.Cipher import AES
import math
import util

__author__ = 'peter'

EXTRA_MSG = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                             'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                             'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                             'YnkK')


def main():
    def cipher(data):
        return util.encryption_oracle(data, mode=AES.MODE_ECB, prepend=b'', append=EXTRA_MSG)[1]
    # Find the blocksize
    blocksize = util.detect_blocksize(cipher)
    print('Blocksize is', blocksize)

    # Find out whether the mode is ECB, if not, quit
    if not util.detect_ecb(cipher(b'A'*500)):
        print('Cipher doesn\'t use ECB mode!')
        return
    else:
        print('Cipher uses ECB mode, cracking...')

    secret = b''
    num_blocks = int(len(cipher(b'')) / blocksize)
    for num_block in range(num_blocks):
        for num_byte in range(blocksize):
            basemsg = b'A' * (blocksize - num_byte - 1)
            d = {}
            for i in range(255):
                b = bytes([i])
                ct = cipher(basemsg + secret + b)
                blocks = list(util.chunks(ct, blocksize))
                d[blocks[num_block]] = b
            ct = cipher(basemsg)
            try:
                secret += d[list(util.chunks(ct, blocksize))[num_block]]
            except KeyError:
                print(len(secret))
                break
    print(len(secret), secret)
    print(len(EXTRA_MSG), EXTRA_MSG)


if __name__ == '__main__':
    main()