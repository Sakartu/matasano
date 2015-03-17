#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
manual_aes_cbc KEY MSG

Options:
"""
import base64

from docopt import docopt
import util

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    msg = bytes(args['MSG'], encoding='utf8')
    key = bytes(args['KEY'], encoding='utf8')
    print('Data is {0} bytes long, last block is {1} bytes'.format(len(msg), len(msg) % 16 or 16))
    prev_ciph = b'\x00' * 16
    blocks = list(util.chunks(msg, 16))
    # Pad last block
    blocks = blocks[:-1] + list(util.chunks(util.pkcs7_pad(blocks[-1]), 16))
    ct = b''
    for b in blocks:
        to_encrypt = util.fixed_xor(b, prev_ciph)
        prev_ciph = util.aes_ecb_encrypt(to_encrypt, key)
        ct += prev_ciph
    print(repr(ct))


if __name__ == '__main__':
    main()