#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
repeating_xor.py KEY MSG...
"""
from docopt import docopt
import util

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    for m in args['MSG']:
        result = util.repeating_xor_decrypt(args['KEY'], m)
        result = ''.join('{:02x}'.format(ord(x)) for x in result)
        print('{0}: {1}'.format(m, result))


if __name__ == '__main__':
    main()