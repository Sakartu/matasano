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
    ct = util.aes_cbc_encrypt(msg, key)
    print(base64.b64encode(ct))


if __name__ == '__main__':
    main()