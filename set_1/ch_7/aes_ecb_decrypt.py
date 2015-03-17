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

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    data = base64.b64decode(''.join(x for x in open(args['INFILE'])))
    key = args['KEY']
    aes = AES.new(key, AES.MODE_ECB)
    result = aes.decrypt(data)
    print(result)


if __name__ == '__main__':
    main()