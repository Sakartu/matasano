#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
hex_to_base64.py HEXSTRING

Options:
"""
import base64

from docopt import docopt

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    bs = bytes.fromhex(args['HEXSTRING'])
    print(base64.b64encode(bs).decode())


if __name__ == '__main__':
    main()
