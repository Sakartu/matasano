#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
fixed_xor.py S1 S2

Options:
"""
import binascii

from docopt import docopt

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    bs1 = bytearray.fromhex(args['S1'])
    bs2 = bytearray.fromhex(args['S2'])
    result = bytearray()
    for b1, b2 in zip(bs1, bs2):
        result.append(b1 ^ b2)
    print(binascii.hexlify(result).decode())


if __name__ == '__main__':
    main()
