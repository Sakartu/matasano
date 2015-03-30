#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
repeating_xor.py [--base64] KEY MSG...
"""
import base64
from docopt import docopt
import util

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    for m in args['MSG']:
        result = util.repeating_xor_decrypt(args['KEY'], bytearray(m))
        if args['--base64']:
            print(base64.b64encode(result))
        else:
            result = ''.join('{:02x}'.format(ord(x)) for x in result)
            print('{0}: {1}'.format(m, result))


if __name__ == '__main__':
    main()