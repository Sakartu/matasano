#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
aes_ecb_decrypt.py KEY INFILE

Options:
"""
import base64

from docopt import docopt
from Crypto.Cipher import AES
import util

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    data = base64.b64decode(''.join(x for x in open(args['INFILE'])))
    key = args['KEY']
    print(util.aes_ecb_decrypt(data, key))


if __name__ == '__main__':
    main()