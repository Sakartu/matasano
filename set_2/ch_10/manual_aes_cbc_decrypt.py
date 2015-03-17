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
    ct = base64.b64decode(args['MSG'])
    key = bytes(args['KEY'], encoding='utf8')
    print('Data is {0} bytes long, last block is {1} bytes'.format(len(ct), len(ct) % 16 or 16))
    prev_ciph = b'\x00' * 16
    blocks = list(util.chunks(ct, 16))
    result = b''
    for b in blocks:
        decrypted = util.aes_ecb_decrypt(b, key)
        result += util.fixed_xor(decrypted, prev_ciph)
        prev_ciph = b
    print(result)


if __name__ == '__main__':
    main()