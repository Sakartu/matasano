#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
repeating_xor.py KEY MSG...
"""
from itertools import cycle
import binascii

from docopt import docopt

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    repeating_key = cycle(args['KEY'])
    for m in args['MSG']:
        result = ''
        for k, c in zip(repeating_key, m):
            result += '{:x}'.format(ord(k) ^ ord(c))
        print('{0}: {1}'.format(m, result))


if __name__ == '__main__':
    main()